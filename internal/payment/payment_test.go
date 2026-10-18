package payment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	x402 "github.com/x402-foundation/x402/go/v2"
	evm "github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	exact "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

const testResource = "http://example.test/v1/pdf/text"

type memoryStore struct {
	mu       sync.Mutex
	rows     map[string]Binding
	failures map[string]int64
	quotas   map[string]failureQuotaRecord
}

type failureQuotaRecord struct {
	Unpaid    int64
	Abandoned int64
	ExpiresAt int64
	Events    map[string]struct{}
}

func (s *memoryStore) Get(ctx context.Context, k string) (*Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rows[k]
	if !ok {
		return nil, nil
	}
	return &b, nil
}
func (s *memoryStore) Put(ctx context.Context, b Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows == nil {
		s.rows = map[string]Binding{}
	}
	if _, ok := s.rows[b.PaymentKey]; ok {
		return ErrConflict
	}
	s.rows[b.PaymentKey] = b
	return nil
}

func (s *memoryStore) Complete(ctx context.Context, b Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.rows[b.PaymentKey]
	if !ok || old.State != preparedState || old.ReservationID != b.ReservationID || old.BodySHA256 != b.BodySHA256 || old.BodyLength != b.BodyLength || old.PaymentProofSHA256 != b.PaymentProofSHA256 {
		return ErrConflict
	}
	s.rows[b.PaymentKey] = b
	return nil
}
func (s *memoryStore) ClaimRetry(ctx context.Context, b Binding, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.rows[b.PaymentKey]
	if !ok || old.State == preparedState || old.PaymentProofSHA256 != b.PaymentProofSHA256 || old.BodySHA256 != b.BodySHA256 || old.BodyLength != b.BodyLength || old.Transaction != b.Transaction || now >= old.RetryUntil || now >= old.ExpiresAt || old.RetryCount >= MaxPaidRetries {
		return ErrRetryLimit
	}
	old.RetryCount++
	s.rows[b.PaymentKey] = old
	return nil
}

func (s *memoryStore) GetFailureQuota(_ context.Context, key string, now int64) (FailureQuota, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.quotas[key]
	if !ok || record.ExpiresAt <= now {
		return FailureQuota{}, nil
	}
	if record.Unpaid+record.Abandoned <= 0 || record.ExpiresAt <= 0 {
		return FailureQuota{}, errors.New("malformed failure quota")
	}
	return FailureQuota{Unpaid: record.Unpaid, Abandonments: record.Abandoned, ExpiresAt: record.ExpiresAt}, nil
}

func (s *memoryStore) IncrementFailureQuota(_ context.Context, key string, expiresAt int64, eventID, eventType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quotas == nil {
		s.quotas = map[string]failureQuotaRecord{}
	}
	record, ok := s.quotas[key]
	if ok && record.ExpiresAt != expiresAt {
		return errors.New("failure quota window changed")
	}
	if record.Events == nil {
		record.Events = map[string]struct{}{}
	}
	if _, duplicate := record.Events[eventID]; duplicate {
		return nil
	}
	if int64(len(record.Events)) >= maxFailedParseEvents {
		return errors.New("failure quota event limit reached")
	}
	if eventType == quotaEventAbandoned {
		record.Abandoned++
	} else if eventType == quotaEventUnpaid {
		record.Unpaid++
	} else {
		return errors.New("invalid failure quota event type")
	}
	record.ExpiresAt = expiresAt
	record.Events[eventID] = struct{}{}
	s.quotas[key] = record
	return nil
}

type countingFacilitator struct {
	calls       atomic.Int32
	verifyCalls atomic.Int32
	err         error
}

func (f *countingFacilitator) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	f.verifyCalls.Add(1)
	if f.err != nil {
		return false, f.err
	}
	return MockFacilitator{}.Verify(ctx, p, a)
}

func (f *countingFacilitator) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return MockFacilitator{}.Settle(ctx, p, a)
}
func signed(t *testing.T) string {
	t.Helper()
	return signedWithKey(t, "0000000000000000000000000000000000000000000000000000000000000001")
}
func signedWithKey(t *testing.T, key string, size ...int64) string {
	t.Helper()
	cfg := protocol.Config{}
	if len(size) != 0 {
		cfg = cfg.ForSize(size[0])
	}
	s, err := signer.NewClientSignerFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := x402.Newx402Client().Register(protocol.Network, exact.NewExactEvmScheme(s, nil)).CreatePaymentPayload(context.Background(), cfg.Requirements(), cfg.Quote(testResource).Resource, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Resource = cfg.Quote(testResource).Resource
	h, err := protocol.Header(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func request(h, body string) protocol.PaymentRequest {
	return protocol.PaymentRequest{Header: h, BodySHA256: protocol.SHA256([]byte(body)), BodyLength: int64(len(body)), Deadline: time.Now().Add(90 * time.Second).Unix()}
}

type quoteCheckingFacilitator struct {
	t                 *testing.T
	verified, settled bool
}

func (f *quoteCheckingFacilitator) check(p types.PaymentPayload) {
	f.t.Helper()
	quote := protocol.Quote(testResource)
	if !reflect.DeepEqual(p.Accepted, quote.Accepts[0]) || !reflect.DeepEqual(p.Resource, quote.Resource) || !reflect.DeepEqual(p.Extensions, quote.Extensions) {
		f.t.Fatal("facilitator received client-controlled quote metadata")
	}
	raw, _ := json.Marshal(p)
	if bytes.Contains(raw, []byte("private-metadata-canary")) {
		f.t.Fatal("facilitator received caller metadata canary")
	}
}
func (f *quoteCheckingFacilitator) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	f.check(p)
	f.verified = true
	return MockFacilitator{}.Verify(ctx, p, a)
}
func (f *quoteCheckingFacilitator) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	f.check(p)
	f.settled = true
	return MockFacilitator{}.Settle(ctx, p, a)
}

func TestFacilitatorReceivesOnlyAuthoritativeQuoteMetadata(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(signed(t))
	if err != nil {
		t.Fatal(err)
	}
	var p types.PaymentPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p.Accepted.Extra["clientExtra"] = "private-metadata-canary"
	p.Resource.Description = "private-metadata-canary"
	p.Resource.ServiceName = "private-metadata-canary"
	p.Resource.Tags = []string{"private-metadata-canary"}
	p.Resource.IconUrl = "https://private-metadata-canary.invalid/icon"
	p.Extensions = map[string]interface{}{"clientExtension": "private-metadata-canary"}
	p.Payload["privateCanary"] = "private-metadata-canary"
	poisoned, err := protocol.Header(p)
	if err != nil {
		t.Fatal(err)
	}
	blocked := &quoteCheckingFacilitator{t: t}
	if out := (Service{Store: &memoryStore{}, Facilitator: blocked, Resource: testResource}).Handle(context.Background(), protocol.PaymentRequest{Header: poisoned, Deadline: time.Now().Add(time.Minute).Unix(), VerifyOnly: true}); out.Pass || out.Status != 402 || blocked.verified {
		t.Fatalf("payload metadata reached facilitator: %+v", out)
	}
	delete(p.Payload, "privateCanary")
	header, err := protocol.Header(p)
	if err != nil {
		t.Fatal(err)
	}
	f := &quoteCheckingFacilitator{t: t}
	s := Service{Store: &memoryStore{}, Facilitator: f, Resource: testResource}
	r := request(header, "document")
	r.VerifyOnly = true
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("verify: %+v", out)
	}
	r.VerifyOnly = false
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("settle: %+v", out)
	}
	if !f.verified || !f.settled {
		t.Fatal("both facilitator operations must be checked")
	}
}

func TestPreflightDoesNotSettleOrWriteBinding(t *testing.T) {
	f := &countingFacilitator{}
	store := &memoryStore{}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	r := protocol.PaymentRequest{Header: signed(t), Deadline: time.Now().Add(time.Minute).Unix(), VerifyOnly: true}
	approved := s.Handle(context.Background(), r)
	if !approved.Pass || approved.Settlement != nil || f.calls.Load() != 0 || len(store.rows) != 0 {
		t.Fatalf("preflight settled or rejected: %+v", approved)
	}
	r.Header = "ordinary invalid header"
	if rejected := s.Handle(context.Background(), r); rejected.Pass || rejected.Status != 402 {
		t.Fatalf("invalid header approved: %+v", rejected)
	}
}
func TestBindingRetriesAndDifferentDocument(t *testing.T) {
	store := &memoryStore{}
	f := &countingFacilitator{}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	h := signed(t)
	r := request(h, "document one")
	first := s.Handle(context.Background(), r)
	if !first.Pass {
		t.Fatalf("first: %+v", first)
	}
	retry := s.Handle(context.Background(), r)
	if !retry.Pass || retry.Settlement.Transaction != first.Settlement.Transaction {
		t.Fatalf("retry: %+v", retry)
	}
	different := s.Handle(context.Background(), request(h, "document two"))
	if different.Pass || different.Status != 409 || different.Error != "payment_document_mismatch" {
		t.Fatalf("different: %+v", different)
	}
	raw, _ := base64.StdEncoding.DecodeString(h)
	var payload any
	_ = json.Unmarshal(raw, &payload)
	pretty, _ := json.MarshalIndent(payload, "", " ")
	r.Header = base64.StdEncoding.EncodeToString(pretty)
	if !s.Handle(context.Background(), r).Pass {
		t.Fatal("serialization changed payment identity")
	}
	if f.calls.Load() != 1 || len(store.rows) != 1 {
		t.Fatalf("settlements=%d rows=%d", f.calls.Load(), len(store.rows))
	}
}

// A settled nonce must remain retryable without asking a provider that now
// considers that nonce consumed. Only identical request bytes may proceed.
func TestSettledPreflightUsesBinding(t *testing.T) {
	store := &memoryStore{}
	f := &countingFacilitator{}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	h := signed(t)
	r := request(h, "document one")
	if first := s.Handle(context.Background(), r); !first.Pass {
		t.Fatalf("first: %+v", first)
	}
	f.err = errors.New("nonce already consumed")
	preflight := protocol.PaymentRequest{Header: h, Deadline: r.Deadline, VerifyOnly: true}
	if out := s.Handle(context.Background(), preflight); !out.Pass || out.Settlement != nil {
		t.Fatalf("preflight: %+v", out)
	}
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("same file: %+v", out)
	}
	if out := s.Handle(context.Background(), request(h, "document two")); out.Pass || out.Error != "payment_document_mismatch" {
		t.Fatalf("different file: %+v", out)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("settlements=%d", f.calls.Load())
	}
}

func TestInvalidSignatureCannotReserveNonce(t *testing.T) {
	h := signed(t)
	raw, _ := base64.StdEncoding.DecodeString(h)
	var p types.PaymentPayload
	_ = json.Unmarshal(raw, &p)
	p.Payload["signature"] = "0x" + repeat("00", 65)
	bad, _ := protocol.Header(p)
	store := &memoryStore{}
	s := Service{Store: store, Facilitator: MockFacilitator{}, Resource: testResource}
	preflight := protocol.PaymentRequest{Header: bad, Deadline: time.Now().Add(time.Minute).Unix(), VerifyOnly: true}
	if out := s.Handle(context.Background(), preflight); out.Pass || out.Status != 402 {
		t.Fatalf("invalid signature preflight: %+v", out)
	}
	if out := s.Handle(context.Background(), request(bad, "doc")); out.Pass {
		t.Fatal("invalid signature passed")
	}
	if len(store.rows) != 0 {
		t.Fatal("invalid signature reserved payment")
	}
	if !s.Handle(context.Background(), request(h, "doc")).Pass {
		t.Fatal("valid payment was blocked")
	}
}
func repeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
func TestConcurrentDifferentDocumentsOneWinner(t *testing.T) {
	store := &memoryStore{}
	s := Service{Store: store, Facilitator: MockFacilitator{}, Resource: testResource}
	h := signed(t)
	start := make(chan struct{})
	out := make(chan protocol.PaymentResponse, 2)
	for _, body := range []string{"one", "two"} {
		go func(body string) { <-start; out <- s.Handle(context.Background(), request(h, body)) }(body)
	}
	close(start)
	a, b := <-out, <-out
	if a.Pass == b.Pass {
		t.Fatalf("expected exactly one pass: %+v %+v", a, b)
	}
	loser := a
	if a.Pass {
		loser = b
	}
	if loser.Error != "payment_document_mismatch" || len(store.rows) != 1 {
		t.Fatalf("loser=%+v", loser)
	}
}
func TestProviderFailureDoesNotClaimUnpaid(t *testing.T) {
	f := &countingFacilitator{err: errors.New("transport timeout")}
	store := &memoryStore{}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	out := s.Handle(context.Background(), request(signed(t), "doc"))
	if out.Pass || out.Status != 502 || out.Error != "payment_unavailable" || len(store.rows) != 0 {
		t.Fatalf("out=%+v", out)
	}
}
func TestRetryDeadlineDoesNotExtend(t *testing.T) {
	now := time.Now()
	store := &memoryStore{}
	f := &countingFacilitator{}
	s := Service{Store: store, Facilitator: f, Resource: testResource, Now: func() time.Time { return now }}
	r := request(signed(t), "doc")
	if !s.Handle(context.Background(), r).Pass {
		t.Fatal("first failed")
	}
	now = now.Add(301 * time.Second)
	r.Deadline = now.Add(time.Minute).Unix()
	out := s.Handle(context.Background(), r)
	if out.Pass || out.Error != "retry_window_expired" || f.calls.Load() != 1 {
		t.Fatalf("out=%+v", out)
	}
}

func (s *memoryStore) Failed(_ context.Context, hash string, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now < s.failures[hash], nil
}
func (s *memoryStore) MarkFailed(_ context.Context, hash string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil {
		s.failures = map[string]int64{}
	}
	if s.failures[hash] <= now {
		s.failures[hash] = now + int64(DocumentFailureLifetime/time.Second)
	}
	return nil
}
