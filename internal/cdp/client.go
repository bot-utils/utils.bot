// Package cdp authenticates fixed x402 REST calls without a Coinbase/JWT SDK.
package cdp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
	"pdfservice/internal/telemetry"
)

const host = "api.cdp.coinbase.com"
const basePath = "/platform/v2/x402/"
const maxResponse = 128 << 10

var (
	ErrCredentials  = errors.New("invalid Coinbase credential configuration")
	ErrUnavailable  = errors.New("Coinbase service unavailable")
	ErrUnauthorized = errors.New("Coinbase authentication or permission rejected")
	ErrResponse     = errors.New("invalid Coinbase response")
)

// HTTPFailure exposes only status and a fixed classification, never the body,
// credential headers or upstream diagnostic text.
type HTTPFailure struct {
	Status int
	Kind   error
}

func (e *HTTPFailure) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Kind, e.Status) }
func (e *HTTPFailure) Unwrap() error { return e.Kind }

type Client struct {
	config         protocol.Config
	keyID          string
	key            any
	receiveAddress string
	http           *http.Client
	now            func() time.Time
}

// Secret-bearing objects remain redacted even in accidental formatted output.
func (*Client) String() string     { return "Coinbase client [redacted]" }
func (c *Client) GoString() string { return c.String() }

func newClient(id, secret, address string) (*Client, error) {
	if len(id) == 0 || len(id) > 256 || !protocol.Hex(address, 20) || strings.EqualFold(address, "0x"+strings.Repeat("0", 40)) {
		return nil, ErrCredentials
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '/') {
			return nil, ErrCredentials
		}
	}
	var key any
	if raw, err := base64.StdEncoding.Strict().DecodeString(secret); err == nil && len(raw) == ed25519.PrivateKeySize {
		derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(derived, raw) != 1 {
			return nil, ErrCredentials
		}
		key = derived
	} else if block, rest := pem.Decode([]byte(secret)); block != nil && len(bytes.TrimSpace(rest)) == 0 {
		ec, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrCredentials
		}
		if ec.Curve != elliptic.P256() {
			return nil, ErrCredentials
		}
		key = ec
	} else {
		return nil, ErrCredentials
	}
	return &Client{keyID: id, key: key, receiveAddress: address, now: time.Now, http: &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4, IdleConnTimeout: 60 * time.Second, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) token(method, path string) (string, error) {
	if !(method == "GET" && path == basePath+"supported" || method == "POST" && (path == basePath+"verify" || path == basePath+"settle")) {
		return "", ErrCredentials
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	alg := "EdDSA"
	if _, ok := c.key.(*ecdsa.PrivateKey); ok {
		alg = "ES256"
	}
	head, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "kid": c.keyID, "nonce": hex.EncodeToString(nonce)})
	now := c.now().Unix()
	claims, _ := json.Marshal(map[string]any{"sub": c.keyID, "iss": "cdp", "nbf": now, "iat": now, "exp": now + 120, "uris": []string{method + " " + host + path}})
	encode := base64.RawURLEncoding.EncodeToString
	message := encode(head) + "." + encode(claims)
	var sig []byte
	switch key := c.key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(key, []byte(message))
	case *ecdsa.PrivateKey:
		h := sha256.Sum256([]byte(message))
		r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
		if err != nil {
			return "", ErrUnavailable
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	default:
		return "", ErrCredentials
	}
	return message + "." + encode(sig), nil
}

func (c *Client) request(ctx context.Context, method, path string, body any, out any) (int, error) {
	jwt, err := c.token(method, path)
	if err != nil {
		return 0, err
	}
	var data []byte
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil || len(data) > protocol.MaxPaymentPayload {
			return 0, ErrResponse
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, bytes.NewReader(data))
	if err != nil {
		return 0, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return resp.StatusCode, &HTTPFailure{resp.StatusCode, ErrUnauthorized}
	}
	// Coinbase also returns normal payment rejections with HTTP 400. Only
	// payment endpoints may decode that status; callers must require false.
	if resp.StatusCode != 200 && !(resp.StatusCode == 400 && method == "POST" && (path == basePath+"verify" || path == basePath+"settle")) {
		return resp.StatusCode, &HTTPFailure{resp.StatusCode, ErrUnavailable}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return resp.StatusCode, ErrResponse
	}
	if jsonwire.Unmarshal(raw, out, maxResponse) != nil {
		return resp.StatusCode, ErrResponse
	}
	return resp.StatusCode, nil
}

type Support struct {
	Base        bool `json:"base"`
	BaseSepolia bool `json:"baseSepolia"`
}

// Check is read-only. It never submits a signed payment or transaction.
func (c *Client) Check(ctx context.Context) (Support, error) {
	var response struct {
		Kinds []struct {
			Version int    `json:"x402Version"`
			Scheme  string `json:"scheme"`
			Network string `json:"network"`
		} `json:"kinds"`
	}
	if _, err := c.request(ctx, "GET", basePath+"supported", nil, &response); err != nil {
		return Support{}, err
	}
	if len(response.Kinds) == 0 || len(response.Kinds) > 256 {
		return Support{}, ErrResponse
	}
	var out Support
	for _, k := range response.Kinds {
		if k.Version == 2 && k.Scheme == "exact" {
			out.Base = out.Base || k.Network == "eip155:8453"
			out.BaseSepolia = out.BaseSepolia || k.Network == protocol.Network
		}
	}
	if !out.BaseSepolia && !out.Base {
		return Support{}, ErrResponse
	}
	return out, nil
}

// Payment requirements come only from trusted deployment configuration and the
// two supported prices. The payment service binds that price to uploaded bytes.
func (c *Client) paymentBody(p types.PaymentPayload) (any, error) {
	a := p.Accepted
	cfg := c.config.ForSize(0)
	if a.Amount == protocol.LargeAmount {
		cfg = cfg.ForSize(protocol.MaxPDF)
	}
	q := cfg.Requirements()
	if p.X402Version != 2 || a.Scheme != q.Scheme || a.Network != q.Network || !strings.EqualFold(a.Asset, q.Asset) || !strings.EqualFold(a.PayTo, q.PayTo) || a.Amount != q.Amount || a.MaxTimeoutSeconds != q.MaxTimeoutSeconds {
		return nil, ErrResponse
	}
	if p.Resource != nil {
		// CDP limits this metadata to 500 characters. Keep the full limits and
		// terms in the customer's quote, but give the facilitator only a short
		// trusted description. EIP-3009 signs the transfer, not this metadata.
		// Construct a new value so neither the caller's quote nor payload is
		// mutated, including when Verify and Settle share it.
		p.Resource = &types.ResourceInfo{URL: p.Resource.URL, MimeType: "application/json", Description: cfg.Description()}
	}
	return struct {
		Version      int                       `json:"x402Version"`
		Payload      types.PaymentPayload      `json:"paymentPayload"`
		Requirements types.PaymentRequirements `json:"paymentRequirements"`
	}{2, p, q}, nil
}

func (c *Client) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (valid bool, err error) {
	started := time.Now()
	status, reason := 0, "invalid_response"
	defer func() {
		if err != nil || !valid {
			var failure *HTTPFailure
			if errors.As(err, &failure) {
				status = failure.Status
			}
			telemetry.ProviderDetail(ctx, "verify", status, diagnosticReason(status, reason, err), telemetry.Milliseconds(started))
		}
	}()
	body, err := c.paymentBody(p)
	if err != nil {
		return false, err
	}
	var out struct {
		Valid  *bool  `json:"isValid"`
		Payer  string `json:"payer"`
		Reason string `json:"invalidReason"`
	}
	status, err = c.request(ctx, "POST", basePath+"verify", body, &out)
	if err != nil {
		return false, err
	}
	if out.Valid == nil || status == 400 && *out.Valid || *out.Valid && !strings.EqualFold(out.Payer, a.Authorization.From) {
		return false, ErrResponse
	}
	reason = out.Reason
	return *out.Valid, nil
}

func (c *Client) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (result *x402.SettleResponse, err error) {
	started := time.Now()
	status := 0
	defer func() {
		if err != nil || result != nil && !result.Success {
			var failure *HTTPFailure
			if errors.As(err, &failure) {
				status = failure.Status
			}
			reason := "invalid_response"
			if result != nil {
				reason = result.ErrorReason
				if result.Transaction != "" {
					reason = "settlement_pending"
				}
			}
			telemetry.ProviderDetail(ctx, "settle", status, diagnosticReason(status, reason, err), telemetry.Milliseconds(started))
		}
	}()
	if c.config.Mode() == protocol.ModeMock {
		return nil, ErrCredentials
	}
	body, err := c.paymentBody(p)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	status, err = c.request(ctx, "POST", basePath+"settle", body, &raw)
	if err != nil {
		return nil, err
	}
	var required struct {
		Success *bool `json:"success"`
	}
	var out x402.SettleResponse
	if jsonwire.Unmarshal(raw, &required, maxResponse) != nil || required.Success == nil || jsonwire.Unmarshal(raw, &out, maxResponse) != nil {
		return nil, ErrResponse
	}
	if status == 400 && out.Success {
		return nil, ErrResponse
	}
	out.ErrorMessage = "" // Provider diagnostic bodies never reach logs/clients.
	out.Extensions = nil
	out.Extra = nil
	cfg := c.config.ForSize(0)
	if p.Accepted.Amount == protocol.LargeAmount {
		cfg = cfg.ForSize(protocol.MaxPDF)
	}
	if out.Success {
		if !cfg.ValidSettlement(&out) || !strings.EqualFold(out.Payer, a.Authorization.From) {
			return nil, ErrResponse
		}
		out = *cfg.SettlementEvidence(&out)
	}
	if !out.Success && out.ErrorReason == "settlement_pending" {
		evidence := cfg.SettlementEvidence(&out)
		if evidence == nil || evidence.ErrorReason != "settlement_pending" || !strings.EqualFold(evidence.Payer, a.Authorization.From) {
			return nil, ErrResponse
		}
		out = *evidence
	}
	return &out, nil
}

// ForPayments enables the real adapter only with an explicit trusted mode.
// Mainnet requires the configured quote recipient to match the SSM address.
func (c *Client) ForPayments(cfg protocol.Config) (*Client, error) {
	if cfg.Mode() == protocol.ModeMock || cfg.Mode() == protocol.ModeBase && !strings.EqualFold(cfg.PayTo(), c.receiveAddress) {
		return nil, ErrCredentials
	}
	copy := *c
	copy.config = cfg
	return &copy, nil
}

// Keep provider-controlled diagnostic text out of logs. Only fixed categories
// and a whitelisted reason survive; credentials and response bodies do not.
func diagnosticReason(status int, reason string, err error) string {
	var failure *HTTPFailure
	if errors.As(err, &failure) {
		status = failure.Status
	}
	switch status {
	case 401, 403:
		return "unauthorized"
	case 402:
		return "billing_required"
	case 429:
		return "rate_limited"
	}
	if status >= 500 {
		return "upstream_failure"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, ErrResponse) {
		return "invalid_response"
	}
	if err != nil {
		return "transport_failure"
	}
	return telemetry.Reason(reason)
}
