package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

func TestCDPPriceTiersUseMatchingRequirementsAndReceipts(t *testing.T) {
	for _, mode := range []string{protocol.ModeBase, protocol.ModeSepolia} {
		for _, size := range []int64{1, protocol.SmallPDFLimit + 1} {
			c, _ := testClient(t)
			cfg, _ := protocol.NewConfig(mode, testPayTo)
			c, err := c.ForPayments(cfg)
			if err != nil {
				t.Fatal(err)
			}
			want := cfg.ForSize(size).Requirements()
			calls := 0
			wrongAmount := false
			c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var body struct {
					Payload      types.PaymentPayload      `json:"paymentPayload"`
					Requirements types.PaymentRequirements `json:"paymentRequirements"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Requirements.Amount != want.Amount || body.Payload.Accepted.Amount != want.Amount || body.Requirements.Network != cfg.Network() || body.Requirements.PayTo != cfg.PayTo() {
					t.Fatal("wrong provider price")
				}
				if strings.HasSuffix(r.URL.Path, "verify") {
					return response(r, 200, `{"isValid":true,"payer":"`+testPayTo+`"}`), nil
				}
				amount := want.Amount
				if wrongAmount {
					if amount == protocol.SmallAmount {
						amount = protocol.LargeAmount
					} else {
						amount = protocol.SmallAmount
					}
				}
				return response(r, 200, `{"success":true,"transaction":"0x`+strings.Repeat("a", 64)+`","network":"`+cfg.Network()+`","payer":"`+testPayTo+`","amount":"`+amount+`"}`), nil
			})
			p := types.PaymentPayload{X402Version: 2, Accepted: want}
			a := evm.ExactEIP3009Payload{}
			a.Authorization.From = testPayTo
			if valid, err := c.Verify(context.Background(), p, a); err != nil || !valid {
				t.Fatalf("verify: %v", err)
			}
			if out, err := c.Settle(context.Background(), p, a); err != nil || out == nil || out.Amount != want.Amount {
				t.Fatalf("settle: %+v %v", out, err)
			}
			wrongAmount = true
			if _, err := c.Settle(context.Background(), p, a); !errors.Is(err, ErrResponse) {
				t.Fatal("wrong amount receipt accepted")
			}
			p.Accepted.Amount = "30000"
			if _, err := c.Verify(context.Background(), p, a); !errors.Is(err, ErrResponse) || calls != 3 {
				t.Fatal("unsupported price reached provider")
			}
		}
	}
}
