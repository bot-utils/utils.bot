package main

import "testing"

func TestPaymentDeploymentFailsClosed(t *testing.T) {
	if paymentReservedConcurrency != 4 {
		t.Fatal("payment concurrency exceeds the two-task plus cancellation-overlap ceiling")
	}
	payee := "0x2222222222222222222222222222222222222222"
	for _, mode := range []string{"mock", "cdp-base", "cdp-base-sepolia"} {
		address := payee
		if mode == "mock" {
			address = ""
		}
		cfg := deploymentPaymentConfig(mode, address, false, true)
		if cfg.Mode != mode || cfg.PayTo == "" {
			t.Fatal("incomplete payment environment")
		}
	}
	for _, tc := range []struct {
		mode, addr  string
		local, edge bool
	}{
		{"cdp-base", payee, true, true}, {"cdp-base", payee, false, false}, {"unknown", payee, false, true}, {"cdp-base", "", false, true}, {"cdp-base", "0x1111111111111111111111111111111111111111", false, true}, {"mock", payee, false, true},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("unsafe deployment accepted")
				}
			}()
			deploymentPaymentConfig(tc.mode, tc.addr, tc.local, tc.edge)
		}()
	}
}
