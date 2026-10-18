package cdp

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

func TestFacilitatorMetadataIsShortWithoutMutatingCustomerQuote(t *testing.T) {
	for _, mode := range []string{protocol.ModeBase, protocol.ModeSepolia} {
		for _, size := range []int64{1, protocol.MaxPDF} {
			cfg, err := protocol.NewConfig(mode, testPayTo)
			if err != nil {
				t.Fatal(err)
			}
			cfg = cfg.ForSize(size)
			quote := cfg.Quote("https://api.utils.bot/v1/pdf/text")
			if !strings.Contains(quote.Resource.Description, protocol.TermsVersion) || !strings.Contains(quote.Resource.Description, "full quoted fee") {
				t.Fatal("customer disclosures missing")
			}
			original := *quote.Resource
			payload := types.PaymentPayload{X402Version: 2, Accepted: quote.Accepts[0], Resource: quote.Resource,
				Payload: map[string]interface{}{"signature": "signature-canary", "authorization": map[string]interface{}{"value": cfg.Requirements().Amount}}}
			before, _ := json.Marshal(payload)
			client, _ := testClient(t)
			client.config = cfg
			for range 2 { // Verify and Settle both call paymentBody.
				body, err := client.paymentBody(payload)
				if err != nil {
					t.Fatal(err)
				}
				wire, _ := json.Marshal(body)
				var envelope struct {
					Payload      types.PaymentPayload      `json:"paymentPayload"`
					Requirements types.PaymentRequirements `json:"paymentRequirements"`
				}
				if json.Unmarshal(wire, &envelope) != nil {
					t.Fatal("invalid envelope")
				}
				r := envelope.Payload.Resource
				if r == nil || r.URL != original.URL || r.MimeType != "application/json" || r.Description != cfg.Description() || utf8.RuneCountInString(r.Description) > 500 {
					t.Fatal("invalid facilitator metadata")
				}
				if envelope.Requirements.Amount != cfg.Requirements().Amount || envelope.Payload.Accepted.Amount != cfg.Requirements().Amount {
					t.Fatal("price changed")
				}
				after, _ := json.Marshal(envelope.Payload.Payload)
				want, _ := json.Marshal(payload.Payload)
				if string(after) != string(want) {
					t.Fatal("signed authorization changed")
				}
			}
			after, _ := json.Marshal(payload)
			if string(before) != string(after) {
				t.Fatal("caller payload or quote mutated")
			}
		}
	}
}
