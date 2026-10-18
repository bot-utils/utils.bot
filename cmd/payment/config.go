package main

import (
	"context"
	"errors"

	"pdfservice/internal/cdp"
	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
)

func configuredFacilitator(ctx context.Context, cfg protocol.Config, client *cdp.Client) (payment.Facilitator, error) {
	if cfg.Mode() == protocol.ModeMock {
		return payment.MockFacilitator{}, nil
	}
	if client == nil {
		return nil, errors.New("Coinbase client unavailable")
	}
	support, err := client.Check(ctx)
	if err != nil || cfg.Mode() == protocol.ModeBase && !support.Base || cfg.Mode() == protocol.ModeSepolia && !support.BaseSepolia {
		return nil, errors.New("Coinbase network unavailable")
	}
	return client.ForPayments(cfg)
}
