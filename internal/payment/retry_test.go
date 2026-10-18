package payment

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

func TestPaidRetryOutlivesSpendAuthorizationButNotFiveMinutes(t *testing.T) {
	now := time.Now()
	f := &countingFacilitator{}
	store := &memoryStore{}
	s := Service{Store: store, Facilitator: f, Resource: testResource, Now: func() time.Time { return now }}
	r := request(signed(t), "document")
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatal(out)
	}
	now = now.Add(299 * time.Second)
	r.Deadline = now.Add(time.Minute).Unix()
	r.VerifyOnly = true
	if out := s.Handle(context.Background(), r); !out.Pass || out.Settlement != nil {
		t.Fatalf("paid preflight after authorization expiry: %+v", out)
	}
	r.VerifyOnly, r.CheckDocument = false, true
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("paid retry after authorization expiry: %+v", out)
	}
	r.CheckDocument = false
	if out := s.Handle(context.Background(), r); !out.Pass || f.calls.Load() != 1 {
		t.Fatalf("retry charged again: %+v", out)
	}
	now = now.Add(time.Second)
	if out := s.Handle(context.Background(), r); out.Pass || out.Error != "retry_window_expired" {
		t.Fatalf("five-minute boundary: %+v", out)
	}
	// The same expired authorization cannot create a new payment without its
	// confirmed binding, including after asynchronous TTL cleanup.
	s.Store = &memoryStore{}
	if out := s.Handle(context.Background(), r); out.Pass || out.Status != 402 || f.calls.Load() != 1 {
		t.Fatalf("expired authorization repaid: %+v", out)
	}
}

func TestConcurrentPaidRetriesClaimExactlyThreeAttempts(t *testing.T) {
	store := &memoryStore{}
	f := &countingFacilitator{}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	r := request(signed(t), "document")
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatal(out)
	}
	r.CheckDocument = true
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := s.Handle(context.Background(), r)
			if out.Pass {
				admitted.Add(1)
			} else if out.Status != 429 || out.Error != "retry_limit_reached" {
				t.Errorf("unexpected retry rejection: %+v", out)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != int32(MaxPaidRetries) || f.calls.Load() != 1 {
		t.Fatalf("admitted %d; settlements %d", admitted.Load(), f.calls.Load())
	}
	r.CheckDocument, r.VerifyOnly = false, true
	if out := s.Handle(context.Background(), r); out.Pass || out.Status != 429 {
		t.Fatalf("exhausted preflight accepted: %+v", out)
	}
}

type concurrentWinnerStore struct {
	*memoryStore
	retryCount int64
}

func (s concurrentWinnerStore) Put(_ context.Context, b Binding) error {
	b.State = paidState
	b.ReservationID = strings.Repeat("12", 16)
	b.Transaction = "0x" + strings.Repeat("ef", 32)
	b.RetryCount = s.retryCount
	s.memoryStore.mu.Lock()
	if s.memoryStore.rows == nil {
		s.memoryStore.rows = map[string]Binding{}
	}
	s.memoryStore.rows[b.PaymentKey] = b
	s.memoryStore.mu.Unlock()
	return ErrConflict
}

func TestCompetingReplicaMustClaimRetryBeforeOutput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		initial    int64
		wantPass   bool
		wantStatus int
		wantRetry  int64
	}{
		{"available retry", 0, true, 0, 1},
		{"exhausted retries", MaxPaidRetries, false, 429, MaxPaidRetries},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &memoryStore{}
			store := concurrentWinnerStore{memoryStore: base, retryCount: tc.initial}
			f := &countingFacilitator{}
			out := (Service{Store: store, Facilitator: f, Resource: testResource}).Handle(context.Background(), request(signed(t), "document"))
			if out.Pass != tc.wantPass || out.Status != tc.wantStatus || f.calls.Load() != 0 {
				t.Fatalf("competing reservation bypassed retry policy: %+v settleCalls=%d", out, f.calls.Load())
			}
			base.mu.Lock()
			defer base.mu.Unlock()
			for _, b := range base.rows {
				if b.RetryCount != tc.wantRetry || b.State != paidState {
					t.Fatalf("retry claim mismatch: %+v", b)
				}
			}
		})
	}
}

type hookedFacilitator struct {
	countingFacilitator
	onSettle   func(context.Context)
	failSettle bool
}

type pendingThenConfirmed struct{ calls atomic.Int32 }

func (f *pendingThenConfirmed) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	return MockFacilitator{}.Verify(ctx, p, a)
}
func (f *pendingThenConfirmed) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	if f.calls.Add(1) == 1 {
		return &x402.SettleResponse{Success: false, ErrorReason: "settlement_pending", Transaction: "0x" + strings.Repeat("ab", 32), Network: x402.Network(protocol.Network), Payer: a.Authorization.From}, nil
	}
	return MockFacilitator{}.Settle(ctx, p, a)
}

func TestPendingSettlementRetriesExactlyOnceAndBindsConfirmation(t *testing.T) {
	store := &memoryStore{}
	f := &pendingThenConfirmed{}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	r := request(signed(t), "document")
	first := s.Handle(context.Background(), r)
	if !first.Pass || first.Settlement == nil || f.calls.Load() != 2 {
		t.Fatalf("pending settlement was not reconciled: %+v calls=%d", first, f.calls.Load())
	}
	if retry := s.Handle(context.Background(), r); !retry.Pass || f.calls.Load() != 2 {
		t.Fatalf("confirmed binding did not suppress another settlement: %+v calls=%d", retry, f.calls.Load())
	}
}

type scriptedPendingFacilitator struct {
	calls      atomic.Int32
	afterFirst func()
	second     func(evm.ExactEIP3009Payload) (*x402.SettleResponse, error)
}

func (f *scriptedPendingFacilitator) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	return MockFacilitator{}.Verify(ctx, p, a)
}

func (f *scriptedPendingFacilitator) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	if f.calls.Add(1) == 1 {
		if f.afterFirst != nil {
			f.afterFirst()
		}
		return pendingReceipt(a.Authorization.From, "ab"), nil
	}
	return f.second(a)
}

func pendingReceipt(payer, pair string) *x402.SettleResponse {
	return &x402.SettleResponse{Success: false, ErrorReason: "settlement_pending", Transaction: "0x" + strings.Repeat(pair, 32), Network: x402.Network(protocol.Network), Payer: payer}
}

func TestPendingSettlementUnresolvedBranchesNeverAuthorize(t *testing.T) {
	validSuccess := func(a evm.ExactEIP3009Payload) *x402.SettleResponse {
		out, err := MockFacilitator{}.Settle(context.Background(), types.PaymentPayload{}, a)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		name       string
		afterFirst func(*time.Time, context.CancelFunc)
		second     func(evm.ExactEIP3009Payload) (*x402.SettleResponse, error)
		wantCalls  int32
	}{
		{"still pending", nil, func(a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
			return pendingReceipt(a.Authorization.From, "ab"), nil
		}, 2},
		{"different pending transaction", nil, func(a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
			return pendingReceipt(a.Authorization.From, "cd"), nil
		}, 2},
		{"retry transport loss", nil, func(evm.ExactEIP3009Payload) (*x402.SettleResponse, error) { return nil, errors.New("reply lost") }, 2},
		{"retry terminal rejection", nil, func(evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
			return &x402.SettleResponse{Success: false, ErrorReason: "invalid_payment"}, nil
		}, 2},
		{"success wrong payer", nil, func(a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
			out := validSuccess(a)
			out.Payer = "0x" + strings.Repeat("3", 40)
			return out, nil
		}, 2},
		{"success wrong network", nil, func(a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
			out := validSuccess(a)
			out.Network = x402.Network(protocol.BaseNetwork)
			return out, nil
		}, 2},
		{"success contradictory pending reason", nil, func(a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
			out := validSuccess(a)
			out.ErrorReason = "settlement_pending"
			return out, nil
		}, 2},
		{"caller cancelled before retry", func(_ *time.Time, cancel context.CancelFunc) { cancel() }, nil, 1},
		{"event deadline expired before retry", func(now *time.Time, _ context.CancelFunc) { *now = now.Add(91 * time.Second) }, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &scriptedPendingFacilitator{second: tc.second}
			if tc.afterFirst != nil {
				f.afterFirst = func() { tc.afterFirst(&now, cancel) }
			}
			store := &memoryStore{}
			s := Service{Store: store, Facilitator: f, Resource: testResource, Now: func() time.Time { return now }}
			r := request(signed(t), "document")
			r.Deadline = now.Add(90 * time.Second).Unix()
			out := s.Handle(ctx, r)
			if out.Pass || out.Status != 502 || out.Settlement == nil || out.Settlement.Success || out.Settlement.ErrorReason != "settlement_pending" || out.Settlement.Transaction != "0x"+strings.Repeat("ab", 32) {
				t.Fatalf("unresolved settlement gained authority or lost original evidence: %+v", out)
			}
			if f.calls.Load() != tc.wantCalls {
				t.Fatalf("settlement calls=%d, want %d", f.calls.Load(), tc.wantCalls)
			}
			store.mu.Lock()
			defer store.mu.Unlock()
			if len(store.rows) != 1 {
				t.Fatalf("prepared reservation count=%d", len(store.rows))
			}
			for _, b := range store.rows {
				if b.State != preparedState || b.Transaction != "" {
					t.Fatalf("unresolved settlement persisted as paid: %+v", b)
				}
			}
		})
	}
}

type providerMetadataFacilitator struct{ success bool }

func (f providerMetadataFacilitator) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	return MockFacilitator{}.Verify(ctx, p, a)
}

func (f providerMetadataFacilitator) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	out, err := MockFacilitator{}.Settle(ctx, p, a)
	if err != nil {
		return nil, err
	}
	out.Extra = map[string]interface{}{"private": "provider detail"}
	out.Extensions = map[string]interface{}{"private": "provider extension"}
	if !f.success {
		out.Success = false
		out.ErrorReason = "settlement_failed"
	}
	return out, nil
}

func TestProviderReceiptMetadataIsNeverReflected(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure evidence", true: "success receipt"}[success], func(t *testing.T) {
			s := Service{Store: &memoryStore{}, Facilitator: providerMetadataFacilitator{success: success}, Resource: testResource}
			out := s.Handle(context.Background(), request(signed(t), "document"))
			if out.Pass != success || out.Settlement == nil || out.Settlement.Extra != nil || out.Settlement.Extensions != nil {
				t.Fatalf("provider metadata reached caller: %+v", out)
			}
			if !success && (out.Status != 502 || out.Settlement.Success || out.Settlement.ErrorReason != "settlement_failed") {
				t.Fatalf("failed settlement gained authority: %+v", out)
			}
		})
	}
}

func (f *hookedFacilitator) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	if f.onSettle != nil {
		f.onSettle(ctx)
	}
	if f.failSettle {
		f.calls.Add(1)
		return nil, errors.New("provider reply lost")
	}
	return f.countingFacilitator.Settle(ctx, p, a)
}

func TestReservationPrecedesTransferAndSurvivesAmbiguousSettlement(t *testing.T) {
	now := time.Now()
	store := &memoryStore{}
	f := &hookedFacilitator{failSettle: true}
	f.onSettle = func(context.Context) {
		if len(store.rows) != 1 {
			t.Fatal("transfer attempted without durable document reservation")
		}
		for _, b := range store.rows {
			if b.State != preparedState || b.Transaction != "" || b.ReservationID == "" {
				t.Fatal("reservation misrepresents payment confirmation")
			}
		}
	}
	s := Service{Store: store, Facilitator: f, Resource: testResource, Now: func() time.Time { return now }}
	r := request(signed(t), "document")
	if out := s.Handle(context.Background(), r); out.Pass || out.Status != 502 {
		t.Fatal(out)
	}
	now = now.Add(301 * time.Second)
	r.Deadline = now.Add(time.Minute).Unix()
	if out := s.Handle(context.Background(), r); out.Pass || out.Error != "payment_confirmation_unavailable" || f.calls.Load() != 1 {
		t.Fatalf("ambiguous payment repeated or mislabeled: %+v", out)
	}
	r.BodySHA256 = protocol.SHA256([]byte("different"))
	if out := s.Handle(context.Background(), r); out.Pass || out.Error != "payment_document_mismatch" || f.calls.Load() != 1 {
		t.Fatalf("reservation changed documents: %+v", out)
	}
}

type failedReservationStore struct{ *memoryStore }

func (s failedReservationStore) Put(context.Context, Binding) error { return errors.New("store down") }

type failedConfirmationStore struct{ *memoryStore }

func (s failedConfirmationStore) Complete(context.Context, Binding) error {
	return errors.New("store down")
}

func TestReservationAndConfirmationWriteFailuresFailClosed(t *testing.T) {
	for _, confirmation := range []bool{false, true} {
		t.Run(map[bool]string{false: "reservation", true: "confirmation"}[confirmation], func(t *testing.T) {
			store := &memoryStore{}
			var durable Store = failedReservationStore{store}
			if confirmation {
				durable = failedConfirmationStore{store}
			}
			f := &countingFacilitator{}
			s := Service{Store: durable, Facilitator: f, Resource: testResource}
			r := request(signed(t), "document")
			out := s.Handle(context.Background(), r)
			if out.Pass || out.Error != "payment_store_unavailable" {
				t.Fatal(out)
			}
			if !confirmation && (f.calls.Load() != 0 || len(store.rows) != 0) {
				t.Fatal("transfer attempted after failed reservation")
			}
			if confirmation {
				if out.Settlement == nil || f.calls.Load() != 1 {
					t.Fatal("confirmed transfer evidence lost")
				}
				if retry := s.Handle(context.Background(), r); retry.Pass || retry.Status != 503 || f.calls.Load() != 1 {
					t.Fatalf("orphan confirmation charged again: %+v", retry)
				}
			}
		})
	}
}

func TestLateConfirmedTransferPersistsForRetry(t *testing.T) {
	now := time.Now()
	store := &memoryStore{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Simulate an authoritative receipt arriving while the HTTP caller leaves.
	s := Service{Store: store, Facilitator: lateReceipt{cancel: cancel}, Resource: testResource, Now: func() time.Time { return now }}
	r := request(signed(t), "document")
	if out := s.Handle(ctx, r); out.Pass || out.Status != 504 || out.Settlement == nil {
		t.Fatalf("cancelled result: %+v", out)
	}
	now = now.Add(200 * time.Second)
	r.Deadline, r.CheckDocument = now.Add(time.Minute).Unix(), true
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("late confirmation not available to retry: %+v", out)
	}
}

func TestConcurrentSameAuthorizationCannotSettleTwice(t *testing.T) {
	store := &memoryStore{}
	entered, release := make(chan struct{}), make(chan struct{})
	f := &hookedFacilitator{onSettle: func(context.Context) { close(entered); <-release }}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	r := request(signed(t), "document")
	first := make(chan protocol.PaymentResponse, 1)
	go func() { first <- s.Handle(context.Background(), r) }()
	<-entered
	for range 8 {
		if out := s.Handle(context.Background(), r); out.Pass || out.Status != 503 {
			t.Errorf("concurrent reservation approved: %+v", out)
		}
	}
	close(release)
	if out := <-first; !out.Pass || f.calls.Load() != 1 {
		t.Fatalf("reservation winner: %+v", out)
	}
}

type lostReservationReply struct{ *memoryStore }

func (s lostReservationReply) Put(ctx context.Context, b Binding) error {
	if err := s.memoryStore.Put(ctx, b); err != nil {
		return err
	}
	return errors.New("reservation reply lost")
}

func TestLostReservationReplyRecoversOnlyOwnReservation(t *testing.T) {
	f := &countingFacilitator{}
	s := Service{Store: lostReservationReply{&memoryStore{}}, Facilitator: f, Resource: testResource}
	if out := s.Handle(context.Background(), request(signed(t), "document")); !out.Pass || f.calls.Load() != 1 {
		t.Fatalf("lost reservation reply: %+v", out)
	}
}

type lateReceipt struct{ cancel context.CancelFunc }

func (f lateReceipt) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	return (MockFacilitator{}).Verify(ctx, p, a)
}
func (f lateReceipt) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	receipt, err := (MockFacilitator{}).Settle(ctx, p, a)
	f.cancel()
	return receipt, err
}
