package cdp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

func TestHTMLProviderBodyUsesFixedPriceAndNoCustomerURL(t *testing.T) {
	c, _ := testClient(t)
	cfg, _ := protocol.NewConfig(protocol.ModeBase, testPayTo)
	cfg = cfg.ForHTML()
	c, err := c.ForPayments(cfg)
	if err != nil {
		t.Fatal(err)
	}
	quote := cfg.Quote(protocol.APIOrigin + protocol.HTMLPath)
	p := types.PaymentPayload{X402Version: 2, Accepted: cfg.Requirements(), Resource: quote.Resource}
	body, err := c.paymentBody(p)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(body)
	if !strings.Contains(string(wire), "URL to Markdown") || strings.Contains(string(wire), "PDF text extraction") || strings.Contains(string(wire), "CERT Polska") {
		t.Fatal("wrong/unbounded facilitator resource", string(wire))
	}
	if len(cfg.Description()) > 500 || cfg.ForSize(protocol.MaxPDF).Requirements().Amount != protocol.SmallAmount {
		t.Fatal("HTML price/description not fixed")
	}
	p.Accepted.Amount = protocol.LargeAmount
	if _, err := c.paymentBody(p); err == nil {
		t.Fatal("PDF large price accepted for HTML")
	}
}
