package protocol

import (
	x402 "github.com/x402-foundation/x402/go/v2"
	"strings"
	"testing"
)

func TestSettlementEvidenceBounds(t *testing.T) {
	s := &x402.SettleResponse{Success: true, Network: Network, Transaction: "0x" + strings.Repeat("ab", 32), Payer: "0x" + strings.Repeat("cd", 20), Amount: Requirements().Amount, Extensions: map[string]any{"unused": strings.Repeat("x", 50000)}}
	if !ValidSettlement(s) {
		t.Fatal("valid settlement rejected")
	}
	evidence := SettlementEvidence(s)
	if evidence == nil || evidence.Extensions != nil || evidence.Extra != nil {
		t.Fatal("unused provider data retained")
	}
	for _, mutate := range []func(*x402.SettleResponse){
		func(s *x402.SettleResponse) { s.Transaction = "arbitrary" }, func(s *x402.SettleResponse) { s.Payer = "" },
		func(s *x402.SettleResponse) { s.Amount = "1" }, func(s *x402.SettleResponse) { s.Network = "eip155:8453" },
		func(s *x402.SettleResponse) { s.ErrorReason = "failure" }, func(s *x402.SettleResponse) { s.Success = false },
	} {
		copy := *s
		mutate(&copy)
		if ValidSettlement(&copy) {
			t.Fatal("invalid approval accepted")
		}
	}
	if Hex("", -1) || Hex("0xgg", 1) || Hex("0x01", 32) {
		t.Fatal("invalid hex accepted")
	}
}
