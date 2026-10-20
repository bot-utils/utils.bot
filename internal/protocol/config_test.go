package protocol

import (
	x402 "github.com/x402-foundation/x402/go/v2"
	"strings"
	"testing"
)

func TestExplicitPaymentConfiguration(t *testing.T) {
	addr := "0x" + strings.Repeat("2", 40)
	for _, mode := range []string{ModeMock, ModeSepolia, ModeBase} {
		payee := addr
		if mode == ModeMock {
			payee = ""
		}
		cfg, err := NewConfig(mode, payee)
		if err != nil {
			t.Fatal(err)
		}
		q := cfg.Quote("https://utils.bot/v1/pdf/text")
		if q.Accepts[0].Amount != "10000" || q.Accepts[0].PayTo != cfg.PayTo() || q.Accepts[0].Network != cfg.Network() {
			t.Fatal("quote mismatch")
		}
		for _, notice := range []string{SourceRiskNotice, "100 MiB", "100 returned pages", "1 MiB text", "full quoted fee applies to successful partial or blank results", TermsVersion} {
			if !strings.Contains(q.Resource.Description, notice) {
				t.Fatal("prepayment disclosure missing", notice)
			}
		}
		if mode == ModeBase && (cfg.Network() != BaseNetwork || cfg.Asset() != BaseAsset || q.Accepts[0].Extra["name"] != "USD Coin" || strings.Contains(q.Resource.Description, "MOCK")) {
			t.Fatal("incorrect Base quote")
		}
		receipt := &x402.SettleResponse{Success: true, Network: x402.Network(cfg.Network()), Payer: addr, Transaction: "0x" + strings.Repeat("a", 64)}
		if !cfg.ValidSettlement(receipt) {
			t.Fatal("own-network settlement rejected")
		}
		receipt.Network = "wrong"
		if cfg.ValidSettlement(receipt) || cfg.SettlementEvidence(receipt) != nil {
			t.Fatal("wrong-network receipt accepted")
		}
	}
	for _, tc := range [][2]string{{"unknown", addr}, {ModeMock, addr}, {ModeBase, ""}, {ModeSepolia, PayTo}, {ModeBase, "0x" + strings.Repeat("0", 40)}, {ModeBase, "0xnothex"}} {
		if _, err := NewConfig(tc[0], tc[1]); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}
