package server

import (
	"context"
	"net/http/httptest"
	"testing"

	"pdfservice/internal/protocol"
)

func TestOriginRejectsNoncanonicalURLsBeforeWork(t *testing.T) {
	for _, path := range []string{"/v1/pdf/text?unexpected=1", "/v1/pdf/text?", "/v1%2fpdf/text", "/docs?url=https://example.invalid/spec"} {
		t.Run(path, func(t *testing.T) {
			s := New("https://utils.bot/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				t.Fatal("noncanonical request reached payment")
				return protocol.PaymentResponse{}, nil
			}, nil)
			r := httptest.NewRequest("POST", path, nil)
			r.Body = unreadableBody{t: t}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 400 || len(s.Slots) != 0 || w.Header().Get("Connection") != "close" {
				t.Fatalf("status=%d slots=%d", w.Code, len(s.Slots))
			}
		})
	}
}

func TestOriginRejectsRangeRequestsBeforeBodyOrPayment(t *testing.T) {
	for _, path := range []string{"/v1/pdf/text", "/assets/swagger-ui-bundle.js", "/openapi", "/health"} {
		for _, header := range []string{"Range", "If-Range"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set(header, "bytes=0-0")
			r.Body = unreadableBody{t: t}
			s := New("https://utils.bot/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				t.Fatal("range request reached payment")
				return protocol.PaymentResponse{}, nil
			}, nil)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 400 || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("range request served: %s %s %d", path, header, w.Code)
			}
		}
	}
}
