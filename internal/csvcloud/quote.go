package csvcloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
)

type Quote struct {
	StartBlock                                                                                                      int64
	ID, KeyID, Stage, JobID, Owner, IntentBinding, ResultBinding, Resource, Amount, Network, Asset, Receiver, Nonce string
	Expires                                                                                                         int64
}
type Keys struct {
	Current  string
	Versions map[string][]byte
}

func (Keys) String() string   { return "CSV binding keys [redacted]" }
func (Keys) GoString() string { return "CSV binding keys [redacted]" }
func (k Keys) nonce(q Quote) (string, error) {
	key := k.Versions[q.KeyID]
	if len(key) != 32 {
		return "", ErrInvalid
	}
	q.Nonce = ""
	raw, _ := json.Marshal(struct {
		Protocol string
		Quote    Quote
	}{"csv-binding-v1", q})
	h := hmac.New(sha256.New, key)
	h.Write(raw)
	return "0x" + hex.EncodeToString(h.Sum(nil)), nil
}
func (k Keys) issue(q Quote, now int64) (Quote, error) {
	if !validAmount(q.Amount) || !opaque(q.ID) || !opaque(q.IntentBinding) || q.Expires <= now || q.Expires > now+180 {
		return q, ErrInvalid
	}
	q.KeyID = k.Current
	n, err := k.nonce(q)
	q.Nonce = n
	return q, err
}
func Requirements(cfg protocol.Config, amount string) types.PaymentRequirements {
	r := cfg.Requirements()
	r.Amount = amount
	return r
}
func (q Quote) Required(cfg protocol.Config) types.PaymentRequired {
	return types.PaymentRequired{X402Version: 2, Resource: &types.ResourceInfo{URL: q.Resource, MimeType: "application/json", Description: "Unlaunched CSV prepared-result payment. Requires csv-binding-v1 signer support."}, Accepts: []types.PaymentRequirements{Requirements(cfg, q.Amount)}, Extensions: map[string]interface{}{"csv-binding-v1": map[string]interface{}{"info": map[string]interface{}{"version": 1, "quote_id": q.ID, "key_id": q.KeyID, "expires_at": q.Expires, "required_nonce": q.Nonce}, "schema": map[string]interface{}{"type": "object", "required": []string{"version", "quote_id", "key_id", "expires_at", "required_nonce"}}}}}
}
func AdmissionQuote(keys Keys, cfg protocol.Config, intentBinding, amount, resource string, now time.Time) (Quote, error) {
	if cfg.Mode() == protocol.ModeMock || !strings.HasSuffix(resource, "/csv/uploads") || !validOrigin(strings.TrimSuffix(resource, "/csv/uploads")) {
		return Quote{}, ErrInvalid
	}
	return keys.issue(Quote{ID: ID(), Stage: "admission", IntentBinding: intentBinding, Resource: resource, Amount: amount, Network: cfg.Network(), Asset: strings.ToLower(cfg.Asset()), Receiver: strings.ToLower(cfg.PayTo()), Expires: now.Unix() + 180}, now.Unix())
}
func resultDigest(m Manifest) string { raw, _ := json.Marshal(m); return Hash(raw) }

// Decode verifies canonical EIP-712 with the official x402 EVM implementation,
// then requires the nonce commitment. CDP Verify remains a separate next step.
func Decode(ctx context.Context, keys Keys, cfg protocol.Config, q Quote, header string, now time.Time) (types.PaymentPayload, evm.ExactEIP3009Payload, error) {
	var p types.PaymentPayload
	var a evm.ExactEIP3009Payload
	invalid := func() (types.PaymentPayload, evm.ExactEIP3009Payload, error) { return p, a, ErrInvalid }
	if ctx.Err() != nil || cfg.Mode() == protocol.ModeMock || len(header) > protocol.MaxPaymentHeader || q.Expires <= now.Unix() || q.Expires > now.Unix()+180 || q.Network != cfg.Network() || !strings.EqualFold(q.Asset, cfg.Asset()) || !strings.EqualFold(q.Receiver, cfg.PayTo()) {
		return invalid()
	}
	wantNonce, err := keys.nonce(q)
	if err != nil || !hmac.Equal([]byte(wantNonce), []byte(q.Nonce)) {
		return invalid()
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(header)
	if err != nil || jsonwire.Unmarshal(raw, &p, protocol.MaxPaymentHeader) != nil || p.X402Version != 2 || p.Resource == nil || p.Resource.URL != q.Resource {
		return invalid()
	}
	want := q.Required(cfg)
	got := p.Accepted
	gotExtra, _ := json.Marshal(got.Extra)
	wantExtra, _ := json.Marshal(want.Accepts[0].Extra)
	if !hmac.Equal(gotExtra, wantExtra) {
		return invalid()
	}
	r := want.Accepts[0]
	if got.Scheme != r.Scheme || got.Network != r.Network || !strings.EqualFold(got.Asset, r.Asset) || !strings.EqualFold(got.PayTo, r.PayTo) || got.Amount != r.Amount || got.MaxTimeoutSeconds != r.MaxTimeoutSeconds {
		return invalid()
	}
	// Echoed extension info must equal the advertised versioned contract; arbitrary
	// unsigned metadata is discarded before provider verification.
	expected, _ := json.Marshal(want.Extensions)
	actual, _ := json.Marshal(p.Extensions)
	if !hmac.Equal(expected, actual) {
		return invalid()
	}
	body, _ := json.Marshal(p.Payload)
	if jsonwire.Decode(body, &a, protocol.MaxPaymentHeader) != nil || !protocol.Hex(a.Authorization.From, 20) || !protocol.Hex(a.Authorization.To, 20) || !protocol.Hex(a.Authorization.Nonce, 32) || !protocol.Hex(a.Signature, 65) || !strings.EqualFold(a.Authorization.Nonce, q.Nonce) || !strings.EqualFold(a.Authorization.To, q.Receiver) || a.Authorization.Value != q.Amount || q.Owner != "" && !strings.EqualFold(a.Authorization.From, q.Owner) {
		return invalid()
	}
	after, e1 := strconv.ParseInt(a.Authorization.ValidAfter, 10, 64)
	before, e2 := strconv.ParseInt(a.Authorization.ValidBefore, 10, 64)
	amount, ok := new(big.Int).SetString(q.Amount, 10)
	if e1 != nil || e2 != nil || !ok || amount.Sign() <= 0 || amount.BitLen() > 64 || amount.String() != q.Amount || after < 0 || before <= now.Unix() || before > q.Expires || after >= now.Unix() || after >= before || strconv.FormatInt(after, 10) != a.Authorization.ValidAfter || strconv.FormatInt(before, 10) != a.Authorization.ValidBefore {
		return invalid()
	}
	chain, _ := new(big.Int).SetString(strings.TrimPrefix(cfg.Network(), "eip155:"), 10)
	hash, err := evm.HashEIP3009Authorization(a.Authorization, chain, cfg.Asset(), cfg.TokenName(), "2")
	if err != nil {
		return invalid()
	}
	sig, _ := hex.DecodeString(strings.TrimPrefix(a.Signature, "0x"))
	valid, err := evm.VerifyEOASignature(hash, sig, common.HexToAddress(a.Authorization.From))
	if err != nil || !valid {
		return invalid()
	}
	p.Accepted = r
	p.Resource = want.Resource
	p.Extensions = nil
	p.Payload = map[string]interface{}{"signature": a.Signature, "authorization": map[string]interface{}{"from": a.Authorization.From, "to": a.Authorization.To, "value": a.Authorization.Value, "validAfter": a.Authorization.ValidAfter, "validBefore": a.Authorization.ValidBefore, "nonce": a.Authorization.Nonce}}
	return p, a, nil
}

type Facilitator interface {
	Verify(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (bool, error)
	Settle(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (*x402.SettleResponse, error)
}

func validAmount(v string) bool {
	n, ok := new(big.Int).SetString(v, 10)
	return ok && n.Sign() > 0 && n.BitLen() <= 64 && n.String() == v
}
func validOrigin(v string) bool {
	u, e := url.Parse(v)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
}
