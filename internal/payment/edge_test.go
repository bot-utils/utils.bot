package payment

import (
	"context"
	"encoding/base64"
	"errors"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
	"strings"
	"testing"
	"time"
)

type delayedVerification struct{ after func() }

func (f delayedVerification) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	valid, err := (MockFacilitator{}).Verify(ctx, p, a)
	f.after()
	return valid, err
}
func (f delayedVerification) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	return (MockFacilitator{}).Settle(ctx, p, a)
}
func TestPreflightDoesNotApproveExpiredAuthorization(t *testing.T) {
	now := time.Now()
	s := Service{Store: &memoryStore{}, Resource: testResource, Now: func() time.Time { return now }, Facilitator: delayedVerification{after: func() { now = now.Add(181 * time.Second) }}}
	out := s.Handle(context.Background(), protocol.PaymentRequest{Header: signed(t), Deadline: now.Add(300 * time.Second).Unix(), VerifyOnly: true})
	if out.Pass || out.Status != 402 {
		t.Fatalf("expired verification approved: %+v", out)
	}
}

type delayedStore struct {
	*memoryStore
	afterGet, afterPut func()
}

type lostReplyStore struct{ *memoryStore }

func (s lostReplyStore) Complete(ctx context.Context, b Binding) error {
	if err := s.memoryStore.Complete(ctx, b); err != nil {
		return err
	}
	return errors.New("write reply lost")
}
func TestLostWriteReplyResolvesWithoutSecondSettlement(t *testing.T) {
	store := &memoryStore{}
	f := &countingFacilitator{}
	s := Service{Store: lostReplyStore{store}, Facilitator: f, Resource: testResource}
	r := request(signed(t), "document")
	first := s.Handle(context.Background(), r)
	if !first.Pass || first.Settlement == nil || f.calls.Load() != 1 || len(store.rows) != 1 {
		t.Fatalf("lost reply did not resolve: %+v", first)
	}
	if retry := s.Handle(context.Background(), r); !retry.Pass || f.calls.Load() != 1 {
		t.Fatalf("lost reply caused second settlement: %+v", retry)
	}
}

func (s delayedStore) Get(ctx context.Context, key string) (*Binding, error) {
	b, err := s.memoryStore.Get(ctx, key)
	if s.afterGet != nil {
		s.afterGet()
	}
	return b, err
}
func (s delayedStore) Complete(ctx context.Context, b Binding) error {
	err := s.memoryStore.Complete(ctx, b)
	if s.afterPut != nil {
		s.afterPut()
	}
	return err
}

func TestRetryExpiresDuringBindingRead(t *testing.T) {
	now := time.Now()
	store := &memoryStore{}
	s := Service{Store: store, Facilitator: MockFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	r := request(signed(t), "document")
	if !s.Handle(context.Background(), r).Pass {
		t.Fatal("first purchase failed")
	}
	r.Deadline = now.Add(400 * time.Second).Unix()
	s.Store = delayedStore{memoryStore: store, afterGet: func() { now = now.Add(301 * time.Second) }}
	out := s.Handle(context.Background(), r)
	if out.Pass || out.Error != "retry_window_expired" {
		t.Fatalf("expired lookup approved: %+v", out)
	}
}

func TestRequestDeadlineExpiresDuringBindingRead(t *testing.T) {
	now := time.Now()
	store := &memoryStore{}
	s := Service{Store: store, Facilitator: MockFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	r := request(signed(t), "document")
	if !s.Handle(context.Background(), r).Pass {
		t.Fatal("first purchase failed")
	}
	r.Deadline = now.Add(time.Second).Unix()
	s.Store = delayedStore{memoryStore: store, afterGet: func() { now = now.Add(2 * time.Second) }}
	if out := s.Handle(context.Background(), r); out.Pass || out.Status != 504 {
		t.Fatalf("request deadline ignored: %+v", out)
	}
}

type cancelReconciliation struct {
	lostReplyStore
	cancel context.CancelFunc
}

func (s *cancelReconciliation) Get(ctx context.Context, key string) (*Binding, error) {
	b, err := s.memoryStore.Get(ctx, key)
	if b != nil && b.State == paidState {
		s.cancel()
	}
	return b, err
}
func TestCancelledLostReplyReconciliationDeniesApproval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &cancelReconciliation{lostReplyStore: lostReplyStore{&memoryStore{}}, cancel: cancel}
	s := Service{Store: store, Facilitator: MockFacilitator{}, Resource: testResource}
	out := s.Handle(ctx, request(signed(t), "document"))
	if out.Pass || out.Status != 504 || out.Settlement == nil {
		t.Fatalf("cancelled reconciliation approved or lost payment evidence: %+v", out)
	}
}
func TestBindingWriteCannotApproveAfterRetryDeadline(t *testing.T) {
	now := time.Now()
	store := &memoryStore{}
	s := Service{Store: delayedStore{memoryStore: store, afterPut: func() { now = now.Add(301 * time.Second) }}, Facilitator: MockFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	out := s.Handle(context.Background(), request(signed(t), "document"))
	if out.Pass || out.Status != 504 || out.Settlement == nil || len(store.rows) != 1 {
		t.Fatalf("late binding approved or evidence lost: %+v", out)
	}
}
func TestCancelledWorkDoesNotBecomeInvalidPayment(t *testing.T) {
	h := signed(t)
	p, a, err := decode(h, testResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (MockFacilitator{}).Settle(ctx, p, a); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation converted into unpaid rejection")
	}
	f := &countingFacilitator{}
	s := Service{Store: &memoryStore{}, Facilitator: f, Resource: testResource}
	if out := s.Handle(ctx, request(h, "document")); out.Pass || out.Status != 504 || f.calls.Load() != 0 {
		t.Fatalf("cancelled request processed: %+v", out)
	}
}
func TestDuplicatePaymentFieldsCannotBind(t *testing.T) {
	h := signed(t)
	raw, _ := base64.StdEncoding.DecodeString(h)
	for _, duplicate := range []string{`"x402Version":2,"x402Version":2`, `"x402Version":2,"X402Version":2`} {
		bad := strings.Replace(string(raw), `"x402Version":2`, duplicate, 1)
		store := &memoryStore{}
		f := &countingFacilitator{}
		s := Service{Store: store, Facilitator: f, Resource: testResource}
		out := s.Handle(context.Background(), request(base64.StdEncoding.EncodeToString([]byte(bad)), "document"))
		if out.Pass || out.Status != 402 || len(store.rows) != 0 || f.calls.Load() != 0 {
			t.Fatalf("ambiguous payment processed: %+v", out)
		}
	}
}
func TestCorruptBindingFailsClosed(t *testing.T) {
	proof := strings.Repeat("ab", 32)
	b := Binding{BodySHA256: protocol.SHA256([]byte("doc")), BodyLength: 3, PaymentProofSHA256: proof, Transaction: "0x" + strings.Repeat("cd", 32), RetryUntil: 100, ExpiresAt: 200}
	r := protocol.PaymentRequest{BodySHA256: b.BodySHA256, BodyLength: b.BodyLength}
	for _, mutate := range []func(*Binding){func(b *Binding) { b.BodySHA256 = "bad" }, func(b *Binding) { b.BodyLength = -1 }, func(b *Binding) { b.ExpiresAt = 0 }} {
		copy := b
		mutate(&copy)
		if out := match(copy, r, proof, 50, "payer"); out.Pass || out.Status != 502 {
			t.Fatalf("corrupt row approved: %+v", out)
		}
	}
}
