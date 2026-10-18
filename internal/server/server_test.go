package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
)

type unreadableBody struct{ t *testing.T }

func (r unreadableBody) Read([]byte) (int, error) {
	r.t.Fatal("body read before payment preflight approved")
	return 0, io.EOF
}
func (r unreadableBody) Close() error { return nil }

func TestInvalidPaymentRejectedBeforeBodyRead(t *testing.T) {
	s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		if !r.VerifyOnly || r.BodySHA256 != "" || r.BodyLength != 0 {
			t.Fatalf("unexpected preflight: %+v", r)
		}
		return protocol.PaymentResponse{Status: 402, Error: "invalid_payment"}, nil
	}, func(context.Context, []byte) (parser.Result, error) {
		t.Fatal("native parsing started")
		return parser.Result{}, nil
	})
	r := httptest.NewRequest("POST", "/v1/pdf/text", nil)
	r.Body = unreadableBody{t: t}
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", "ordinary-invalid-header")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 402 || len(s.Slots) != 0 {
		t.Fatalf("status=%d slots=%d", w.Code, len(s.Slots))
	}
}

func TestRetryLimitRejectedBeforeBodyReadOrWorkers(t *testing.T) {
	s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		if !r.VerifyOnly {
			t.Fatal("retry limit checked after upload")
		}
		return protocol.PaymentResponse{Status: 429, Error: "retry_limit_reached"}, nil
	}, func(context.Context, []byte) (parser.Result, error) {
		t.Fatal("exhausted retry started workers")
		return parser.Result{}, nil
	})
	r := httptest.NewRequest("POST", "/v1/pdf/text", nil)
	r.Body = unreadableBody{t: t}
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", "fixture")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 429 || !strings.Contains(w.Body.String(), "retry_limit_reached") || len(s.Slots) != 0 {
		t.Fatalf("retry rejection: %d %s", w.Code, w.Body.String())
	}
}

func TestUnpaidNeverParsesOrPays(t *testing.T) {
	s := New("http://example.test/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		t.Fatal("payment called")
		return protocol.PaymentResponse{}, nil
	}, func(context.Context, []byte) (parser.Result, error) {
		t.Fatal("parse called")
		return parser.Result{}, nil
	})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("pdf")))
	if w.Code != 402 || w.Header().Get("PAYMENT-REQUIRED") == "" {
		t.Fatalf("status=%d", w.Code)
	}
}
func TestPaymentTransportFailureStopsParsing(t *testing.T) {
	var parses atomic.Int32
	s := New("http://example.test/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		return protocol.PaymentResponse{}, errors.New("timeout")
	}, func(context.Context, []byte) (parser.Result, error) { parses.Add(1); return parser.Result{}, nil })
	r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("pdf"))
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", "fixture")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 502 || parses.Load() != 0 || w.Header().Get("PAYMENT-REQUIRED") != "" {
		t.Fatalf("status=%d parses=%d", w.Code, parses.Load())
	}
}
func TestCapacityRefusalBeforePayment(t *testing.T) {
	s := New("test", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		t.Fatal("charged full capacity")
		return protocol.PaymentResponse{}, nil
	}, nil)
	if cap(s.Slots) != 1 {
		t.Fatal("small task must admit only one upload/parser")
	}
	for range cap(s.Slots) {
		s.Slots <- struct{}{}
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/pdf/text", strings.NewReader("pdf"))
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", "fixture")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	health := httptest.NewRecorder()
	s.Handler().ServeHTTP(health, httptest.NewRequest("GET", "/health", nil))
	if health.Code != 200 {
		t.Fatal("health blocked")
	}
}
