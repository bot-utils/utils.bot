package main

import (
	"context"
	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
	"testing"
)

func TestProviderSelectionNeverFallsBackToMock(t *testing.T) {
	f, err := configuredFacilitator(context.Background(), protocol.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.(payment.MockFacilitator); !ok {
		t.Fatal("mock selection failed")
	}
	for _, mode := range []string{protocol.ModeBase, protocol.ModeSepolia} {
		cfg, _ := protocol.NewConfig(mode, "0x2222222222222222222222222222222222222222")
		f, err := configuredFacilitator(context.Background(), cfg, nil)
		if err == nil || f != nil {
			t.Fatal("real mode silently fell back to mock")
		}
	}
}
