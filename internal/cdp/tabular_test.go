package cdp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

func TestTabularExplicitPricePrivateMetadataAndSingleAttempt(t *testing.T) {
	c, _ := testClient(t)
	cfg := c.config
	req := cfg.Requirements()
	req.Amount = "12345"
	resource := "https://utils.bot/csv/jobs/private-job/payment"
	bound, e := c.ForTabular(cfg, req, resource)
	if e != nil {
		t.Fatal(e)
	}
	a := evm.ExactEIP3009Payload{Signature: "0x" + strings.Repeat("a", 130), Authorization: evm.ExactEIP3009Authorization{From: "0x1111111111111111111111111111111111111111", To: req.PayTo, Value: req.Amount, ValidAfter: "1799999999", ValidBefore: "1800000180", Nonce: "0x" + strings.Repeat("b", 64)}}
	b, _ := json.Marshal(a)
	var payload map[string]interface{}
	_ = json.Unmarshal(b, &payload)
	p := types.PaymentPayload{X402Version: 2, Accepted: req, Resource: &types.ResourceInfo{URL: resource}, Extensions: map[string]interface{}{"csv-binding-v1": "private-result"}, Payload: payload}
	calls := 0
	c.http.Transport = csvRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "private-job") || strings.Contains(string(raw), "private-result") || strings.Contains(string(raw), "csv-binding-v1") {
			t.Fatal("private metadata disclosed")
		}
		if !strings.Contains(string(raw), `"amount":"12345"`) || r.Header.Get("Authorization") == "" {
			t.Fatal("unbound request")
		}
		body := `{"isValid":true,"payer":"` + a.Authorization.From + `"}`
		if strings.HasSuffix(r.URL.Path, "settle") {
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"error":"private-provider-detail"}`)), Header: http.Header{}}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	}) // Bound client is a shallow copy, sharing its hardened HTTP client.
	if ok, e := bound.Verify(t.Context(), p, a); e != nil || !ok {
		t.Fatal(e)
	}
	if _, e := bound.Settle(t.Context(), p, a); e == nil {
		t.Fatal("upstream failure accepted")
	}
	if calls != 2 {
		t.Fatal("request retried", calls)
	}
	p.Payload["customer-content"] = "secret"
	if _, e := bound.Verify(t.Context(), p, a); e != ErrResponse || calls != 2 {
		t.Fatal("untyped payload disclosed", e)
	}
	mock := protocol.Config{}
	if _, e = c.ForTabular(mock, req, resource); e == nil {
		t.Fatal("mock accepted")
	}
}

type csvRoundTrip func(*http.Request) (*http.Response, error)

func (f csvRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
