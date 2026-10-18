package payment

import (
	"context"
	"strings"
	"testing"

	"pdfservice/internal/protocol"
)

func TestIdenticalPDFHasIndependentPurchasesAndRetryLimits(t *testing.T) {
	for _, samePayer := range []bool{true, false} {
		name := "different_payers"
		if samePayer {
			name = "same_payer_new_nonce"
		}
		t.Run(name, func(t *testing.T) {
			firstHeader := signed(t)
			key := strings.Repeat("0", 63) + "2"
			if samePayer {
				key = strings.Repeat("0", 63) + "1"
			}
			secondHeader := signedWithKey(t, key)
			store := &memoryStore{}
			f := &countingFacilitator{}
			s := Service{Store: store, Facilitator: f, Resource: testResource}
			requests := []protocol.PaymentRequest{request(firstHeader, "identical PDF"), request(secondHeader, "identical PDF")}
			// Independent invocations must not contend for the PDF's hash. They
			// reserve distinct payment identities, even for the same payer.
			results := make(chan protocol.PaymentResponse, 2)
			for _, r := range requests {
				go func(r protocol.PaymentRequest) { results <- s.Handle(context.Background(), r) }(r)
			}
			for range 2 {
				if out := <-results; !out.Pass {
					t.Fatalf("independent purchase: %+v", out)
				}
			}
			if f.calls.Load() != 2 || len(store.rows) != 2 {
				t.Fatalf("settlements=%d rows=%d", f.calls.Load(), len(store.rows))
			}
			for _, b := range store.rows {
				if b.BodySHA256 != requests[0].BodySHA256 || b.State != paidState || b.RetryCount != 0 {
					t.Fatalf("wrong independent binding: %+v", b)
				}
			}
			for _, r := range requests {
				r.CheckDocument = true
				for range MaxPaidRetries {
					if out := s.Handle(context.Background(), r); !out.Pass {
						t.Fatalf("independent retry budget: %+v", out)
					}
				}
				if out := s.Handle(context.Background(), r); out.Pass || out.Status != 429 {
					t.Fatalf("retry limit: %+v", out)
				}
			}
			// Exhausted retries on ALL older payments must not create a per-PDF
			// ban: another purchase still receives its own binding and budget.
			r := request(signed(t), "identical PDF")
			r.CheckDocument = true
			if out := s.Handle(context.Background(), r); !out.Pass {
				t.Fatalf("new payment blocked by old retry limits: %+v", out)
			}
			r.CheckDocument = false
			if out := s.Handle(context.Background(), r); !out.Pass || f.calls.Load() != 3 || len(store.rows) != 3 {
				t.Fatalf("fresh paid purchase: %+v", out)
			}
			// This never lets an old payment purchase different bytes.
			r = requests[0]
			r.BodySHA256 = protocol.SHA256([]byte("different PDF"))
			if out := s.Handle(context.Background(), r); out.Pass || out.Error != "payment_document_mismatch" || f.calls.Load() != 3 {
				t.Fatalf("old payment rebound: %+v", out)
			}
		})
	}
}
