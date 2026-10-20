package server

import (
	"bytes"
	"context"
	"encoding/json"
	x402 "github.com/x402-foundation/x402/go/v2"
	"log/slog"
	"net/http/httptest"
	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
	"strings"
	"testing"
)

func validApproval() protocol.PaymentResponse {
	return protocol.PaymentResponse{Pass: true, Settlement: &x402.SettleResponse{Success: true, Network: protocol.Network, Transaction: "0x" + strings.Repeat("ab", 32), Payer: "0x" + strings.Repeat("cd", 20)}}
}

func TestEarlyRefusalsDoNotDrainBody(t *testing.T) {
	for _, name := range []string{"unpaid", "duplicate", "wrong-type", "encoded", "oversized", "capacity", "draining"} {
		t.Run(name, func(t *testing.T) {
			s := New("http://example.test/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				t.Fatal("payment reached on early refusal")
				return protocol.PaymentResponse{}, nil
			}, nil)
			r := httptest.NewRequest("POST", "/v1/pdf/text", nil)
			r.Body = unreadableBody{t: t}
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			r.Header.Set("Content-Type", "application/pdf")
			want := 400
			switch name {
			case "unpaid":
				r.Header.Del("PAYMENT-SIGNATURE")
				want = 402
			case "duplicate":
				r.Header.Add("PAYMENT-SIGNATURE", "second")
			case "wrong-type":
				r.Header.Set("Content-Type", "text/plain")
				want = 415
			case "encoded":
				r.Header.Set("Content-Encoding", "gzip")
				want = 415
			case "oversized":
				r.ContentLength = protocol.MaxPDF + 1
				want = 413
			case "capacity":
				for range cap(s.Slots) {
					s.Slots <- struct{}{}
				}
				want = 429
			case "draining":
				s.Draining.Store(true)
				want = 503
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Connection") != "close" {
				t.Fatalf("refusal=%d close=%q", w.Code, w.Header().Get("Connection"))
			}
			if want == 429 && w.Header().Get("Retry-After") == "" {
				t.Fatal("no retry guidance")
			}
		})
	}
}

func TestContradictoryApprovalNeverParses(t *testing.T) {
	for _, stage := range []string{"preflight", "settlement"} {
		for _, kind := range []string{"status", "error", "evidence"} {
			t.Run(stage+"/"+kind, func(t *testing.T) {
				s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
					if (r.VerifyOnly || r.CheckDocument) && stage == "settlement" {
						return protocol.PaymentResponse{Pass: true}, nil
					}
					out := validApproval()
					if r.VerifyOnly || r.CheckDocument || r.DocumentFailed {
						out.Settlement = nil
					}
					switch kind {
					case "status":
						out.Status = 400
					case "error":
						out.Error = "failure"
					case "evidence":
						if r.VerifyOnly || r.CheckDocument || r.DocumentFailed {
							out.Settlement = validApproval().Settlement
						} else {
							out.Settlement.Transaction = "invalid"
						}
					}
					return out, nil
				}, func(context.Context, []byte) (parser.Result, error) {
					if stage != "settlement" {
						t.Fatal("invalid preflight approval reached parser")
					}
					return parser.Result{}, nil
				})
				r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("document"))
				r.Header.Set("Content-Type", "application/pdf")
				r.Header.Set("PAYMENT-SIGNATURE", "fixture")
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != 502 || len(s.Slots) != 0 || w.Header().Get("PAYMENT-RESPONSE") != "" {
					t.Fatalf("bad approval handling: %d", w.Code)
				}
			})
		}
	}
}

func TestPanicReleasesCapacityAndLogsNoRequestData(t *testing.T) {
	var logs bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(prior)
	calls := 0
	s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		if r.VerifyOnly || r.CheckDocument || r.DocumentFailed {
			return protocol.PaymentResponse{Pass: true}, nil
		}
		return validApproval(), nil
	}, func(context.Context, []byte) (parser.Result, error) {
		calls++
		if calls == 1 {
			panic("private document text")
		}
		return parser.Result{}, nil
	})
	for _, status := range []int{502, 200} {
		r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("private document text"))
		r.Header.Set("Content-Type", "application/pdf")
		r.Header.Set("PAYMENT-SIGNATURE", "private signature")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != status || len(s.Slots) != 0 {
			t.Fatalf("status=%d slots=%d", w.Code, len(s.Slots))
		}
	}
	query := httptest.NewRequest("POST", "/v1/pdf/text?private-query=yes", strings.NewReader("private document text"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, query)
	if w.Code != 400 || calls != 2 {
		t.Fatal("unsupported query reached parsing")
	}
	for _, private := range []string{"private document text", "private signature", "private-query"} {
		if strings.Contains(logs.String(), private) {
			t.Fatal("request data entered logs")
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil {
			t.Fatal("invalid log JSON")
		}
		if entry["msg"] == "pdf request completed" && entry["elapsed_ms"] == nil {
			t.Fatal("completion missing timing")
		}
	}
}
