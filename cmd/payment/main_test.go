package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
)

type invocationGuard struct{ calls int }

func (g *invocationGuard) Handle(context.Context, protocol.PaymentRequest) protocol.PaymentResponse {
	g.calls++
	panic("malformed Lambda event reached payment service")
}

func TestLambdaRuntimeHandler(t *testing.T) {
	// Exercise the raw Lambda payload adapter, which does not run when tests call
	// the payment service directly.
	runtime := handler(payment.Service{})
	data, err := runtime.Invoke(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("Lambda invocation failed: %v", err)
	}
	var response protocol.PaymentResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Pass || response.Status != 504 || response.Error != "request_deadline" {
		t.Fatalf("unexpected rejection response: %+v", response)
	}
}

func TestLambdaRuntimeRejectsAmbiguousOrUnboundedControlJSON(t *testing.T) {
	guard := &invocationGuard{}
	runtime := handler(guard)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"duplicate", []byte(`{"deadline":1,"deadline":2}`)},
		{"case duplicate", []byte(`{"deadline":1,"Deadline":2}`)},
		{"wrong field case", []byte(`{"Deadline":1}`)},
		{"unknown", []byte(`{"deadline":1,"unexpected":true}`)},
		{"null", []byte(`null`)},
		{"scalar", []byte(`"request"`)},
		{"trailing", []byte(`{} {}`)},
		{"oversized", []byte(`{"header":"` + strings.Repeat("a", protocol.MaxPaymentPayload) + `"}`)},
	} {
		encoded, err := runtime.Invoke(context.Background(), tc.data)
		if err != nil {
			t.Fatalf("%s: Lambda invocation failed: %v", tc.name, err)
		}
		var response protocol.PaymentResponse
		if err := json.Unmarshal(encoded, &response); err != nil {
			t.Fatal(err)
		}
		if response.Pass || response.Status != 400 || response.Error != "invalid_payment_request" {
			t.Fatalf("%s: malformed request accepted: %+v", tc.name, response)
		}
	}
	if guard.calls != 0 {
		t.Fatalf("malformed events invoked payment service %d times", guard.calls)
	}
}
