package main

import (
	"encoding/hex"
	"strings"
)

type paymentConfig struct{ Mode, PayTo string }

func deploymentPaymentConfig(mode, payTo string, local, edge bool) paymentConfig {
	if mode == "" {
		mode = "mock"
	}
	if mode == "mock" {
		if payTo != "" && payTo != "0x1111111111111111111111111111111111111111" {
			panic("mock payee cannot change")
		}
		return paymentConfig{mode, "0x1111111111111111111111111111111111111111"}
	}
	if (mode != "cdp-base" && mode != "cdp-base-sepolia") || local || !edge {
		panic("CDP requires the private canonical HTTPS deployment")
	}
	if len(payTo) != 42 || !strings.HasPrefix(payTo, "0x") {
		panic("explicit CDP payee required")
	}
	if _, err := hex.DecodeString(payTo[2:]); err != nil || payTo == "0x"+strings.Repeat("0", 40) || payTo == "0x1111111111111111111111111111111111111111" {
		panic("invalid CDP payee")
	}
	return paymentConfig{mode, strings.ToLower(payTo)}
}
