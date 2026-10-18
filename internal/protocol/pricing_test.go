package protocol

import (
	"strings"
	"testing"

	x402 "github.com/x402-foundation/x402/go/v2"
)

func TestSizePricingBoundariesAndSettlementAmounts(t *testing.T) {
	for _, mode := range []string{ModeMock, ModeSepolia, ModeBase} {
		payee := "0x" + strings.Repeat("2", 40)
		if mode == ModeMock {
			payee = ""
		}
		base, err := NewConfig(mode, payee)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int64{-1, 0, 1, SmallPDFLimit - 1, SmallPDFLimit, SmallPDFLimit + 1, MaxPDF} {
			cfg := base.ForSize(size)
			want := SmallAmount
			if size > SmallPDFLimit {
				want = LargeAmount
			}
			q := cfg.Quote("https://api.utils.bot/v1/pdf/text")
			if q.Accepts[0].Amount != want || base.Requirements().Amount != SmallAmount {
				t.Fatalf("mode=%s size=%d quote=%+v", mode, size, q)
			}
			r := &x402.SettleResponse{Success: true, Network: x402.Network(cfg.Network()), Payer: cfg.PayTo(), Transaction: "0x" + strings.Repeat("a", 64), Amount: want}
			if !cfg.ValidSettlement(r) || cfg.SettlementEvidence(r) == nil {
				t.Fatal("correct tier receipt rejected")
			}
			if want == SmallAmount {
				r.Amount = LargeAmount
			} else {
				r.Amount = SmallAmount
			}
			if cfg.ValidSettlement(r) || cfg.SettlementEvidence(r) != nil {
				t.Fatal("wrong tier receipt accepted")
			}
		}
	}
}
