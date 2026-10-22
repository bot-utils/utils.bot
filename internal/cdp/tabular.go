package cdp

import (
	"context"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
)

// BoundClient uses the existing authenticated, no-proxy/no-redirect CDP transport
// for one separately configured CSV quote. Existing PDF/HTML paths are unchanged.
type BoundClient struct {
	client       *Client
	requirements types.PaymentRequirements
	resource     string
}

func (*BoundClient) GoString() string { return "Coinbase CSV client [redacted]" }
func (*BoundClient) String() string   { return "Coinbase CSV client [redacted]" }
func (c *Client) ForTabular(cfg protocol.Config, req types.PaymentRequirements, resource string) (*BoundClient, error) {
	n, ok := new(big.Int).SetString(req.Amount, 10)
	u, e := url.Parse(resource)
	want := cfg.Requirements()
	if cfg.Mode() == protocol.ModeMock || !ok || n.Sign() <= 0 || n.BitLen() > 64 || n.String() != req.Amount || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !(u.Path == "/csv/uploads" || strings.HasPrefix(u.Path, "/csv/jobs/") && strings.HasSuffix(u.Path, "/payment")) || cfg.Mode() == protocol.ModeBase && !strings.EqualFold(cfg.PayTo(), c.receiveAddress) || req.Scheme != want.Scheme || req.Network != want.Network || !strings.EqualFold(req.Asset, want.Asset) || !strings.EqualFold(req.PayTo, want.PayTo) || req.MaxTimeoutSeconds != 180 {
		return nil, ErrCredentials
	}
	// Canonical trusted token-domain fields; no arbitrary caller extras reach CDP.
	req.Extra = want.Extra
	copy := *c
	copy.config = cfg
	return &BoundClient{client: &copy, requirements: req, resource: resource}, nil
}
func (c *BoundClient) body(p types.PaymentPayload, auth evm.ExactEIP3009Payload) (any, error) {
	a, w := p.Accepted, c.requirements
	if p.X402Version != 2 || p.Resource == nil || p.Resource.URL != c.resource || a.Scheme != w.Scheme || a.Network != w.Network || !strings.EqualFold(a.Asset, w.Asset) || !strings.EqualFold(a.PayTo, w.PayTo) || a.Amount != w.Amount || a.MaxTimeoutSeconds != w.MaxTimeoutSeconds {
		return nil, ErrResponse
	}
	raw, _ := json.Marshal(p.Payload)
	var supplied evm.ExactEIP3009Payload
	if jsonwire.Decode(raw, &supplied, protocol.MaxPaymentHeader) != nil || supplied != auth || !protocol.Hex(auth.Authorization.From, 20) || !protocol.Hex(auth.Authorization.To, 20) || !protocol.Hex(auth.Authorization.Nonce, 32) || !protocol.Hex(auth.Signature, 65) || !strings.EqualFold(auth.Authorization.To, w.PayTo) || auth.Authorization.Value != w.Amount {
		return nil, ErrResponse
	}
	// The signed nonce carries job binding. Do not disclose private job URLs,
	// manifest hashes or custom extension metadata to the facilitator/Bazaar.
	p.Resource = nil
	p.Extensions = nil
	p.Accepted = w
	return struct {
		Version      int                       `json:"x402Version"`
		Payload      types.PaymentPayload      `json:"paymentPayload"`
		Requirements types.PaymentRequirements `json:"paymentRequirements"`
	}{2, p, w}, nil
}
func (c *BoundClient) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	body, err := c.body(p, a)
	if err != nil {
		return false, err
	}
	var out struct {
		Valid *bool  `json:"isValid"`
		Payer string `json:"payer"`
	}
	status, err := c.client.request(ctx, "POST", basePath+"verify", body, &out)
	if err != nil {
		return false, err
	}
	if out.Valid == nil || status == 400 && *out.Valid || *out.Valid && !strings.EqualFold(out.Payer, a.Authorization.From) {
		return false, ErrResponse
	}
	return *out.Valid, nil
}
func (c *BoundClient) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	body, err := c.body(p, a)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	status, err := c.client.request(ctx, "POST", basePath+"settle", body, &raw)
	if err != nil {
		return nil, err
	}
	var required struct {
		Success *bool `json:"success"`
	}
	var out x402.SettleResponse
	if jsonwire.Unmarshal(raw, &required, maxResponse) != nil || required.Success == nil || jsonwire.Unmarshal(raw, &out, maxResponse) != nil || status == 400 && out.Success {
		return nil, ErrResponse
	}
	if out.Success && (!protocol.Hex(out.Transaction, 32) || !strings.EqualFold(out.Payer, a.Authorization.From) || string(out.Network) != c.requirements.Network || out.Amount != "" && out.Amount != c.requirements.Amount) {
		return nil, ErrResponse
	}
	if out.Transaction != "" && (!protocol.Hex(out.Transaction, 32) || !strings.EqualFold(out.Payer, a.Authorization.From) || string(out.Network) != c.requirements.Network) {
		return nil, ErrResponse
	}
	// Success is provider acknowledgement, not our selected finalized-chain proof.
	out.ErrorMessage = ""
	out.Extensions = nil
	out.Extra = nil
	return &out, nil
}
