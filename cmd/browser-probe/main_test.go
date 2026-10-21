package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestProbeRejectsCustomerInputsWithoutStartingBrowser(t *testing.T) {
	for _, wire := range []string{`{"url":"https://private-customer.example/secret"}`, `{"fixture":"private-payment-canary"}`, `[]`, `null`, strings.Repeat("x", 513)} {
		got, err := probe(context.Background(), json.RawMessage(wire))
		if err != nil || got.Code != "invalid_probe_input" || got.OK {
			t.Fatal(got, err)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "private") {
			t.Fatal("customer input in probe output")
		}
	}
}
