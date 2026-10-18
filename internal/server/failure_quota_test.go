package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	exact "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/parser"
	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
)

type failedUploadBody struct{}

func (failedUploadBody) Read([]byte) (int, error) { return 0, errors.New("client upload stopped") }
func (failedUploadBody) Close() error             { return nil }

type withdrawAfterPreflightFacilitator struct{ verifies int }

func (f *withdrawAfterPreflightFacilitator) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	f.verifies++
	if f.verifies > 1 {
		return false, nil
	}
	return payment.MockFacilitator{}.Verify(ctx, p, a)
}
func (*withdrawAfterPreflightFacilitator) Settle(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	return nil, errors.New("settlement followed definitive verification rejection")
}

func TestDisconnectedInvokeStillRecordsLambdaDefinitiveRejection(t *testing.T) {
	resource := "https://utils.bot/v1/pdf/text"
	store := &nativeTestStore{}
	paymentService := payment.Service{Store: store, Facilitator: &withdrawAfterPreflightFacilitator{}, Resource: resource}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	s := New(resource, func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		if !r.VerifyOnly && !r.CheckDocument && !r.DocumentFailed && r.RecordOutcome == "" {
			// The HTTP caller and Invoke client disappear, while the already-started
			// Lambda runs under its independent runtime context.
			cancelRequest()
			r.Deadline = time.Now().Add(20 * time.Second).Unix()
			completed := paymentService.Handle(context.Background(), r)
			if completed.Pass || completed.Status != 402 || completed.Error != "invalid_payment" {
				t.Fatalf("private invocation did not finish definitively: %+v", completed)
			}
			return protocol.PaymentResponse{}, context.Canceled
		}
		return paymentService.Handle(ctx, r), nil
	}, func(context.Context, []byte) (parser.Result, error) {
		return parser.Result{PageCount: 1, Pages: []parser.Page{{Index: 1, Text: "text"}}}, nil
	})
	clientSigner, err := signer.NewClientSignerFromPrivateKey("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := x402.Newx402Client().Register(protocol.Network, exact.NewExactEvmScheme(clientSigner, nil)).CreatePaymentPayload(context.Background(), protocol.Requirements(), protocol.Quote(resource).Resource, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload.Resource = protocol.Quote(resource).Resource
	header, err := protocol.Header(payload)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("valid PDF")).WithContext(requestCtx)
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", header)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if requestCtx.Err() == nil || w.Code != 502 {
		t.Fatalf("caller was not disconnected: status=%d err=%v", w.Code, requestCtx.Err())
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var unpaid int64
	for _, quota := range store.quotas {
		unpaid += quota[0]
	}
	if unpaid != 1 {
		t.Fatalf("late Lambda rejection was not accounted exactly once: quotas=%+v", store.quotas)
	}
}

func TestVerifiedPartialUploadRecordsOneAbandonmentWithoutDocumentMetadata(t *testing.T) {
	var calls []protocol.PaymentRequest
	s := New("https://utils.bot/v1/pdf/text", func(callCtx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		calls = append(calls, r)
		if r.RecordOutcome != "" {
			deadline, ok := callCtx.Deadline()
			if r.RecordOutcome != protocol.PaymentOutcomeAbandoned || r.BodySHA256 != "" || r.BodyLength != 0 || !ok || time.Until(deadline) > 5*time.Second || r.Deadline != deadline.Unix() {
				t.Fatalf("unsafe abandonment callback: %+v", r)
			}
		}
		return protocol.PaymentResponse{Pass: true}, nil
	}, func(context.Context, []byte) (parser.Result, error) {
		t.Fatal("partial upload reached parser")
		return parser.Result{}, nil
	})
	r := httptest.NewRequest("POST", "/v1/pdf/text", nil)
	r.Body = failedUploadBody{}
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", "fixture")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 || len(calls) != 2 || !calls[0].VerifyOnly || calls[1].RecordOutcome != protocol.PaymentOutcomeAbandoned || calls[0].TraceID == "" || calls[0].TraceID != calls[1].TraceID {
		t.Fatalf("partial upload accounting: status=%d calls=%+v", w.Code, calls)
	}
	for _, call := range calls {
		if call.CheckDocument || call.DocumentFailed || !call.VerifyOnly && call.RecordOutcome == "" {
			t.Fatalf("partial upload claimed retry or reached settlement: %+v", call)
		}
	}
}

func TestCompletedParseDoesNotDuplicateLambdaUnpaidOutcome(t *testing.T) {
	for _, tc := range []struct {
		name        string
		final       protocol.PaymentResponse
		wantStatus  int
		wantOutcome int
	}{
		{name: "definitive invalid payment", final: protocol.PaymentResponse{Status: 402, Error: "invalid_payment"}, wantStatus: 402},
		{name: "provider unavailable", final: protocol.PaymentResponse{Status: 502, Error: "payment_unavailable"}, wantStatus: 502},
		{name: "confirmation unknown", final: protocol.PaymentResponse{Status: 503, Error: "payment_confirmation_unavailable"}, wantStatus: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcomes := 0
			s := New("https://utils.bot/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				switch {
				case r.VerifyOnly, r.CheckDocument:
					return protocol.PaymentResponse{Pass: true}, nil
				case r.RecordOutcome != "":
					outcomes++
					t.Fatalf("server duplicated Lambda-owned completed outcome: %+v", r)
					return protocol.PaymentResponse{}, nil
				default:
					return tc.final, nil
				}
			}, func(context.Context, []byte) (parser.Result, error) {
				return parser.Result{PageCount: 1, Pages: []parser.Page{{Index: 1, Text: "text"}}}, nil
			})
			r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("valid PDF"))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.wantStatus || outcomes != tc.wantOutcome {
				t.Fatalf("status=%d outcomes=%d body=%s", w.Code, outcomes, w.Body.String())
			}
		})
	}
}

func TestFailureQuotaRefusesBeforeUploadAndExposesBoundedWait(t *testing.T) {
	for _, stage := range []string{"preflight", "document-check"} {
		t.Run(stage, func(t *testing.T) {
			s := New("https://utils.bot/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				if r.VerifyOnly && stage == "document-check" {
					return protocol.PaymentResponse{Pass: true}, nil
				}
				return protocol.PaymentResponse{Status: 429, Error: "unpaid_compute_quota_exceeded", RetryAfter: 123}, nil
			}, nil)
			r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("document"))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			if stage == "preflight" {
				r.Body = unreadableBody{t: t}
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 429 || w.Header().Get("Retry-After") != "123" || w.Header().Get("Payment-Response") != "" || len(s.Slots) != 0 {
				t.Fatalf("quota refusal lost safety or retry guidance: %d %+v", w.Code, w.Header())
			}
		})
	}
}

func TestCompletedDocumentFailureStillCountsAfterCallerCancellation(t *testing.T) {
	for _, completedFailure := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		failures := 0
		abandonments := 0
		s := New("https://utils.bot/v1/pdf/text", func(callCtx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
			if r.DocumentFailed {
				failures++
				deadline, ok := callCtx.Deadline()
				if callCtx.Err() != nil || !ok || time.Until(deadline) > 5*time.Second || r.Deadline != deadline.Unix() {
					t.Fatal("completed failure accounting inherited a cancelled or unbounded deadline")
				}
			} else if r.RecordOutcome == protocol.PaymentOutcomeAbandoned {
				abandonments++
				if r.BodySHA256 != "" || r.BodyLength != 0 {
					t.Fatal("abandonment disclosed partial upload metadata")
				}
			} else if !r.VerifyOnly && !r.CheckDocument {
				t.Fatal("failed parse reached payment collection")
			}
			return protocol.PaymentResponse{Pass: true}, nil
		}, func(context.Context, []byte) (parser.Result, error) {
			cancel()
			if completedFailure {
				return parser.Result{Attempts: []parser.Attempt{{Engine: "pdfium", Outcome: "document_error"}, {Engine: "poppler", Outcome: "document_error"}}}, parser.ErrDocument
			}
			return parser.Result{Attempts: []parser.Attempt{{Engine: "pdfium", Outcome: "timeout"}}}, parser.ErrSetup
		})
		r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("document")).WithContext(ctx)
		r.Header.Set("Content-Type", "application/pdf")
		r.Header.Set("PAYMENT-SIGNATURE", "fixture")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		cancel()
		want := 0
		if completedFailure {
			want = 1
		}
		wantAbandonments := 1 - want
		if failures != want || abandonments != wantAbandonments || len(s.Slots) != 0 || w.Header().Get("Payment-Response") != "" {
			t.Fatalf("failure classification lost after cancellation: completed=%t failures=%d abandonments=%d", completedFailure, failures, abandonments)
		}
	}
}

func TestInvalidQuotaControlCannotReadBodyOrCreateBackoff(t *testing.T) {
	for _, response := range []protocol.PaymentResponse{
		{Pass: true, RetryAfter: 1},
		{Status: 429, Error: "unpaid_compute_quota_exceeded"},
		{Status: 429, Error: "unpaid_compute_quota_exceeded", RetryAfter: -1},
		{Status: 429, Error: "unpaid_compute_quota_exceeded", RetryAfter: 3601},
		{Status: 402, Error: "invalid_payment", RetryAfter: 1},
	} {
		s := New("https://utils.bot/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) { return response, nil }, nil)
		r := httptest.NewRequest("POST", "/v1/pdf/text", nil)
		r.Header.Set("Content-Type", "application/pdf")
		r.Header.Set("PAYMENT-SIGNATURE", "fixture")
		r.Body = unreadableBody{t: t}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 502 || w.Header().Get("Retry-After") != "" || len(s.Slots) != 0 {
			t.Fatalf("invalid control accepted: %+v status=%d", response, w.Code)
		}
	}
}

func TestFailureQuotaAcceptsFullHourBackoff(t *testing.T) {
	for _, seconds := range []int64{1, 900, 901, 3599, 3600} {
		if !validPaymentBackoff(protocol.PaymentResponse{Status: 429, Error: "unpaid_compute_quota_exceeded", RetryAfter: seconds}) {
			t.Fatalf("valid one-hour-window backoff rejected: %d", seconds)
		}
	}
	if protocol.FailedParseWindow != time.Hour {
		t.Fatal("failed-parse quota must use a full one-hour window")
	}
}
