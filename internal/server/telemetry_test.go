package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
	"pdfservice/internal/telemetry"
)

type failingResponse struct {
	header http.Header
	short  bool
}

func (w *failingResponse) Header() http.Header { return w.header }
func (*failingResponse) WriteHeader(int)       {}
func (w *failingResponse) Write([]byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, errors.New("customer connection lost")
}

func TestReceiverTelemetryCorrelatesAndDetectsPaidFailures(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	for _, outcome := range []string{"success", "document", "service", "write", "short-write", "contradiction"} {
		t.Run(outcome, func(t *testing.T) {
			var buf bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
			trace := ""
			calls := 0
			s := New("http://example.test/v1/pdf/text", func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				calls++
				if len(r.TraceID) != 32 || telemetry.Trace(ctx) != r.TraceID || trace != "" && trace != r.TraceID {
					t.Fatal("broken correlation")
				}
				trace = r.TraceID
				if r.VerifyOnly || r.CheckDocument || r.DocumentFailed {
					return protocol.PaymentResponse{Pass: true}, nil
				}
				if outcome == "contradiction" {
					paid := validApproval()
					paid.Status = 502
					paid.Error = "invalid_payment_response"
					return paid, nil
				}
				return validApproval(), nil
			}, func(context.Context, []byte) (parser.Result, error) {

				result := parser.Result{Attempts: []parser.Attempt{{Engine: "pdfium", Outcome: "document_error"}, {Engine: "poppler", Outcome: "success"}}}
				switch outcome {
				case "document":
					return result, parser.ErrDocument
				case "service":
					return result, parser.ErrSetup
				}
				return result, nil
			})
			r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("%PDF-1.7\nprivate customer text"))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", "private payment header")
			r.Header.Set("X-Request-ID", "attacker controlled")
			r.RemoteAddr = "198.51.100.42:12345"
			r.Header.Set("X-Forwarded-For", "203.0.113.42")
			r.Header.Set("User-Agent", "private requester user agent")
			var w http.ResponseWriter = httptest.NewRecorder()
			if outcome == "write" || outcome == "short-write" {
				w = &failingResponse{header: make(http.Header), short: outcome == "short-write"}
			}
			s.Handler().ServeHTTP(w, r)
			expectedCalls := 3
			if outcome == "document" || outcome == "service" {
				expectedCalls = 2
			}
			if calls != expectedCalls || w.Header().Get("X-Request-ID") != trace {
				t.Fatal("correlation absent")
			}
			var record map[string]any
			if json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record) != nil {
				t.Fatal(buf.String())
			}
			paid := float64(0)
			if outcome == "write" || outcome == "short-write" || outcome == "contradiction" {
				paid = 1
			}
			if record["paid_service_failures"] != paid || record["fallback_attempts"] != float64(1) {
				t.Fatal(record)
			}
			for _, secret := range []string{"private customer", "private payment", "attacker controlled", "198.51.100.42", "203.0.113.42", "private requester user agent", validApproval().Settlement.Payer, validApproval().Settlement.Transaction} {
				if strings.Contains(buf.String(), secret) {
					t.Fatal("customer information logged")
				}
			}
		})
	}
}

func TestLeanLogsLocateFailedStageWithoutCustomerMetadata(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		if r.VerifyOnly || r.CheckDocument {
			return protocol.PaymentResponse{Pass: true}, nil
		}
		return protocol.PaymentResponse{}, errors.New("SECRET provider body and wallet")
	}, func(context.Context, []byte) (parser.Result, error) {
		return parser.Result{Attempts: []parser.Attempt{{Engine: "pdfium", Outcome: "success"}}}, nil
	})
	r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("%PDF PRIVATE DOCUMENT"))
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", "PRIVATE AUTHORIZATION")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var record map[string]any
	if json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record) != nil {
		t.Fatal(buf.String())
	}
	if w.Code != 502 || record["stage"] != "settle" || record["code"] != "payment_unavailable" || record["pdfium"] != "success" || record["schema"] != float64(5) {
		t.Fatal(record)
	}
	for _, field := range []string{"verify_ms", "upload_ms", "check_ms", "parse_ms", "prepare_ms", "settle_ms"} {
		n, ok := record[field].(float64)
		if !ok || n < 0 || n > 120000 {
			t.Fatal(field, record)
		}
	}
	if len(buf.Bytes()) > 2048 || strings.Contains(buf.String(), "PRIVATE") || strings.Contains(buf.String(), "SECRET") {
		t.Fatal("excess log content", buf.String())
	}
}
