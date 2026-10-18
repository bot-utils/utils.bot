package payment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"pdfservice/internal/protocol"
)

func TestEveryDocumentOperationEnforcesActualSizePrice(t *testing.T) {
	for _, size := range []int64{1, protocol.SmallPDFLimit, protocol.SmallPDFLimit + 1, protocol.MaxPDF} {
		for _, paidSize := range []int64{1, protocol.MaxPDF} {
			for _, operation := range []string{"check", "failure", "settle"} {
				store := &memoryStore{}
				f := &countingFacilitator{}
				s := Service{Store: store, Facilitator: f, Resource: testResource}
				h := signedWithKey(t, strings.Repeat("0", 63)+"1", paidSize)
				r := protocol.PaymentRequest{Header: h, BodySHA256: protocol.SHA256([]byte("test document")), BodyLength: size, Deadline: time.Now().Add(5 * time.Second).Unix(), CheckDocument: operation == "check", DocumentFailed: operation == "failure"}
				out := s.Handle(context.Background(), r)
				matches := (size > protocol.SmallPDFLimit) == (paidSize > protocol.SmallPDFLimit)
				if !matches {
					if out.Pass || out.Status != 402 || out.Error != "payment_amount_mismatch" || f.calls.Load() != 0 || f.verifyCalls.Load() != 0 || len(store.rows) != 0 {
						t.Fatalf("size=%d paidSize=%d op=%s: %+v", size, paidSize, operation, out)
					}
				} else if !out.Pass {
					t.Fatalf("matching price size=%d op=%s: %+v", size, operation, out)
				}
			}
		}
	}
}

func TestPreflightAcceptsBothPricesButNeverSettlesOrBinds(t *testing.T) {
	for _, size := range []int64{1, protocol.MaxPDF} {
		store := &memoryStore{}
		f := &countingFacilitator{}
		s := Service{Store: store, Facilitator: f, Resource: testResource}
		r := protocol.PaymentRequest{Header: signedWithKey(t, strings.Repeat("0", 63)+"1", size), VerifyOnly: true, Deadline: time.Now().Add(10 * time.Second).Unix()}
		if out := s.Handle(context.Background(), r); !out.Pass || f.calls.Load() != 0 || f.verifyCalls.Load() != 1 || len(store.rows) != 0 {
			t.Fatalf("preflight %+v", out)
		}
	}
}

func TestPriceCannotBeChangedWithoutMatchingSignedAuthorization(t *testing.T) {
	h := signed(t)
	raw, _ := base64.StdEncoding.DecodeString(h)
	var p map[string]any
	if json.Unmarshal(raw, &p) != nil {
		t.Fatal("decode")
	}
	p["accepted"].(map[string]any)["amount"] = protocol.LargeAmount
	h, _ = protocol.Header(p)
	f := &countingFacilitator{}
	s := Service{Store: &memoryStore{}, Facilitator: f, Resource: testResource}
	r := request(h, "test")
	r.BodyLength = protocol.MaxPDF
	if out := s.Handle(context.Background(), r); out.Pass || out.Status != 402 || f.calls.Load() != 0 {
		t.Fatalf("forged amount: %+v", out)
	}
}
