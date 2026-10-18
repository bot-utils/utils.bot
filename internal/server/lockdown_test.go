package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
)

func TestUnusedRequestsNeverReadBodyOrInvokePayment(t *testing.T) {
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{"PUT", "/v1/pdf/text", 405}, {"DELETE", "/", 405},
		{"POST", "/missing", 404}, {"GET", "/", 400}, {"HEAD", "/health", 400},
		{"GET", "/v100/words", 404}, {"HEAD", "/v100/words", 404},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			s := New("http://example.test/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				t.Fatal("payment reached")
				return protocol.PaymentResponse{}, nil
			}, nil)
			r := httptest.NewRequest(test.method, test.path, strings.NewReader("unused"))
			r.Body = unreadableBody{t: t}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != test.status || w.Header().Get("Connection") != "close" {
				t.Fatalf("status=%d close=%q", w.Code, w.Header().Get("Connection"))
			}
		})
	}
}

func TestDuplicateContentHeadersRejectedBeforePayment(t *testing.T) {
	for _, name := range []string{"Content-Type", "Content-Encoding"} {
		t.Run(name, func(t *testing.T) {
			s := New("http://example.test/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				t.Fatal("payment reached")
				return protocol.PaymentResponse{}, nil
			}, nil)
			r := httptest.NewRequest("POST", "/v1/pdf/text", nil)
			r.Body = unreadableBody{t: t}
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			r.Header.Set("Content-Type", "application/pdf")
			if name == "Content-Type" {
				r.Header.Add(name, "text/plain")
			} else {
				r.Header.Add(name, "identity")
				r.Header.Add(name, "gzip")
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 400 || len(s.Slots) != 0 {
				t.Fatalf("status=%d slots=%d", w.Code, len(s.Slots))
			}
		})
	}
}

func TestCanceledApprovalCannotReadUploadOrParse(t *testing.T) {
	for _, stage := range []string{"before", "preflight", "settlement"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before" {
				cancel()
			}
			s := New("http://example.test/v1/pdf/text", func(_ context.Context, p protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				if stage == "before" {
					t.Fatal("canceled request reached payment")
				}
				if p.VerifyOnly || p.CheckDocument || p.DocumentFailed {
					if stage == "preflight" {
						cancel()
					}
					return protocol.PaymentResponse{Pass: true}, nil
				}
				cancel()
				return validApproval(), nil
			}, func(context.Context, []byte) (parser.Result, error) {
				if stage != "settlement" {
					t.Fatal("expired preflight reached parser")
				}
				return parser.Result{}, nil
			})
			r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("pdf")).WithContext(ctx)
			if stage != "settlement" {
				r.Body = unreadableBody{t: t}
			}
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 504 || len(s.Slots) != 0 {
				t.Fatalf("status=%d slots=%d", w.Code, len(s.Slots))
			}
			if stage == "settlement" && w.Header().Get("PAYMENT-RESPONSE") == "" {
				t.Fatal("lost settlement evidence")
			}
		})
	}
}
