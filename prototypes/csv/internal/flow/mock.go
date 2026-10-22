package flow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"utils.bot/csvprototype/internal/tabular"
)

// Claims are a synthetic HMAC format, deliberately not x402 or a spend authorization.
type Claims struct {
	Stage    string `json:"stage"`
	Owner    string `json:"owner"`
	Nonce    string `json:"nonce"`
	Resource string `json:"resource"`
	Binding  string `json:"binding"`
	Amount   string `json:"amount"`
	Expires  int64  `json:"expires_at"`
}
type Challenge struct {
	Mode     string `json:"mode"`
	Stage    string `json:"stage"`
	Resource string `json:"resource"`
	Binding  string `json:"binding"`
	Amount   string `json:"amount"`
	Expires  int64  `json:"expires_at"`
}
type Provider interface {
	Verify(string, Challenge, bool, time.Time) (Claims, error)
	Settle(context.Context, string, Claims) (string, error)
	Lookup(context.Context, string) (string, error)
}

// MockProvider has no HTTP client, network address, real wallet, or funded path.
// Key is a synthetic rehearsal key and is never provided to the parser worker.
type MockProvider struct {
	Store *Store
	Key   string
	Fault string
}

func SignMock(key string, c Claims) string {
	raw, _ := json.Marshal(c)
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + keyed(key, "mock-signature-v1", body)
}
func (m *MockProvider) Verify(proof string, want Challenge, allowExpired bool, now time.Time) (Claims, error) {
	var c Claims
	if !secret(m.Key) {
		return c, fail(503, "mock_provider_unavailable")
	}
	if len(proof) > 4096 {
		return c, fail(402, "invalid_mock_payment")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 2 || !secret(parts[1]) {
		return c, fail(402, "invalid_mock_payment")
	}
	if !same(parts[1], keyed(m.Key, "mock-signature-v1", parts[0])) {
		return c, fail(402, "invalid_mock_signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || tabular.StrictJSON(raw, &c) != nil || !secret(c.Owner) || !secret(c.Nonce) || !secret(c.Binding) {
		return Claims{}, fail(402, "invalid_mock_payment")
	}
	if c.Stage != want.Stage || c.Resource != want.Resource || want.Binding != "" && c.Binding != want.Binding || c.Amount != want.Amount {
		return Claims{}, fail(402, "payment_binding_mismatch")
	}
	if c.Expires > now.Add(180*time.Second).Unix() || c.Expires <= 0 || !allowExpired && c.Expires <= now.Unix() {
		return Claims{}, fail(402, "payment_expired")
	}

	return c, nil
}
func (m *MockProvider) Settle(_ context.Context, id string, c Claims) (string, error) {
	outcome := "PAID"
	if m.Fault == "reject" || m.Fault == "rejected-reply-lost" {
		outcome = "UNPAID"
	}
	e := m.Store.tx(true, func(d *database) error {
		if _, exists := d.Provider[id]; exists {
			return errors.New("duplicate_settlement_call")
		}
		d.Provider[id] = outcome
		d.SettlementCalls++
		return nil
	})
	if e != nil {
		return "", e
	}
	if m.Fault == "accepted-reply-lost" || m.Fault == "rejected-reply-lost" {
		return "", errors.New("synthetic_reply_lost")
	}
	return outcome, nil
}
func (m *MockProvider) Lookup(_ context.Context, id string) (string, error) {
	var result string
	e := m.Store.tx(false, func(d *database) error { result = d.Provider[id]; return nil })
	if e != nil {
		return "", e
	}
	if result == "" {
		return "UNKNOWN", nil
	}
	return result, nil
}
