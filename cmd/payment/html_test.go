package main

import (
	"context"
	"testing"

	"pdfservice/internal/protocol"
)

func TestUnknownToolNeverFallsBackToAnotherService(t *testing.T) {
	h := paymentHandler{}
	for _, tool := range []string{"html", "pdf", "other"} {
		out := h.Handle(context.Background(), protocol.PaymentRequest{Tool: tool})
		if out.Pass || out.Status != 400 {
			t.Fatal(tool, out)
		}
	}
}
