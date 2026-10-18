package payment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"pdfservice/internal/protocol"
)

func TestPaymentTelemetrySeparatesVerifySettleRetryAndMismatch(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(previous)
	header := signed(t)
	s := Service{Store: &memoryStore{}, Facilitator: &countingFacilitator{}, Resource: testResource}
	r := request(header, "%PDF private content")
	r.TraceID = strings.Repeat("a", 32)
	verify := r
	verify.VerifyOnly = true
	verify.BodySHA256 = ""
	verify.BodyLength = 0
	for _, q := range []protocol.PaymentRequest{verify, r, r, request(header, "different private content")} {
		s.Handle(context.Background(), q)
	}
	failed := Service{Store: &memoryStore{}, Facilitator: &countingFacilitator{err: errors.New("secret provider response")}, Resource: testResource}
	failed.Handle(context.Background(), verify)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatal("not one record per invocation")
	}
	wants := []map[string]int{{"verify_calls": 1, "settlement_attempts": 0}, {"settlement_attempts": 1, "settlement_confirmed": 1, "binding_created": 1}, {"paid_retries": 1, "settlement_attempts": 0}, {"paid_retries": 0, "settlement_attempts": 0}, {"verify_calls": 1, "provider_failures": 1}}
	for i, line := range lines {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			t.Fatal(line)
		}
		for key, want := range wants[i] {
			if record[key] != float64(want) {
				t.Fatalf("record %d %s=%v want %d", i, key, record[key], want)
			}
		}
	}
	for _, forbidden := range []string{header, r.BodySHA256, "private content", "secret provider response", "0x"} {
		if strings.Contains(buf.String(), forbidden) {
			t.Fatal("payment/customer data logged")
		}
	}
}
func TestResolvedBindingWriteDoesNotReportStorageOutage(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(previous)
	// A write acknowledged by storage but whose reply was lost resolves by read.
	store := &lostReplyStore{memoryStore: &memoryStore{}}
	s := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource, Now: time.Now}
	out := s.Handle(context.Background(), request(signed(t), "pdf"))
	if !out.Pass {
		t.Fatal(out.Error)
	}
	var record map[string]any
	if json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record) != nil || record["binding_failures"] != float64(0) {
		t.Fatal(buf.String())
	}
}

func TestPaymentPanicIsGenericAndCannotLeakThroughLambdaRuntime(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(previous)
	service := Service{Now: func() time.Time { panic("PRIVATE provider body / wallet / authorization") }}
	r := request("PRIVATE payment header", "PRIVATE document")
	out := service.Handle(context.Background(), r)
	if out.Pass || out.Status != 502 || out.Error != "payment_unavailable" || out.Settlement != nil {
		t.Fatal(out)
	}
	var record map[string]any
	if json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record) != nil || record["handler_panic"] != true || record["status"] != float64(502) || record["code"] != "payment_unavailable" {
		t.Fatal(buf.String())
	}
	if strings.Contains(buf.String(), "PRIVATE") || strings.Contains(buf.String(), r.BodySHA256) || strings.Count(buf.String(), "\n") != 1 {
		t.Fatal("panic/customer details leaked", buf.String())
	}
	// The recovery is per invocation; the next request can still be handled.
	service.Now = time.Now
	if next := service.Handle(context.Background(), protocol.PaymentRequest{}); next.Status != 504 {
		t.Fatal("panic affected later invocation", next)
	}
}
