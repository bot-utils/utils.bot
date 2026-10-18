package payment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/ethereum/go-ethereum/crypto"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

const secondTestPrivateKey = "0000000000000000000000000000000000000000000000000000000000000002"

func signedWithValidity(t *testing.T, privateKey string, validAfter, validBefore int64) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(signedWithKey(t, privateKey))
	if err != nil {
		t.Fatal(err)
	}
	var payload types.PaymentPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	nested, _ := json.Marshal(payload.Payload)
	var exact evm.ExactEIP3009Payload
	if err := json.Unmarshal(nested, &exact); err != nil {
		t.Fatal(err)
	}
	exact.Authorization.ValidAfter = strconv.FormatInt(validAfter, 10)
	exact.Authorization.ValidBefore = strconv.FormatInt(validBefore, 10)
	hash, err := evm.HashEIP3009Authorization(exact.Authorization, big.NewInt(84532), protocol.Asset, "USDC", "2")
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := crypto.Sign(hash, key)
	if err != nil {
		t.Fatal(err)
	}
	signature[64] += 27
	exact.Signature = evm.BytesToHex(signature)
	payload.Payload = exact.ToMap()
	header, err := protocol.Header(payload)
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func headerPayer(t *testing.T, header string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var payload types.PaymentPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	nested, _ := json.Marshal(payload.Payload)
	var exact evm.ExactEIP3009Payload
	if err := json.Unmarshal(nested, &exact); err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(exact.Authorization.From)
}

func recordFailedParses(t *testing.T, service Service, privateKey string, count int) {
	t.Helper()
	for i := range count {
		r := request(signedWithKey(t, privateKey), fmt.Sprintf("unique failed PDF %d", i))
		r.DocumentFailed = true
		r.Deadline = service.now().Add(documentFailureDeadlineOffset).Unix()
		if out := service.Handle(context.Background(), r); !out.Pass {
			t.Fatalf("record failure %d: %+v", i, out)
		}
	}
}

func recordOutcome(t *testing.T, service Service, header, trace, outcome string) protocol.PaymentResponse {
	t.Helper()
	r := protocol.PaymentRequest{
		TraceID: trace, Header: header, RecordOutcome: outcome,
		Deadline: service.now().Add(documentFailureDeadlineOffset).Unix(),
	}
	return service.Handle(context.Background(), r)
}

type rejectingFacilitator struct{}

func (rejectingFacilitator) Verify(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (bool, error) {
	return false, nil
}
func (rejectingFacilitator) Settle(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	return nil, errors.New("settlement must not follow rejected verification")
}

func TestResourceOutcomesShareQuotaAndRemainIdempotent(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	header := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Minute).Unix(), now.Add(2*time.Minute).Unix())
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}

	for i := range 3 {
		rejected := service
		rejected.Facilitator = rejectingFacilitator{}
		r := request(signedWithKey(t, strings.Repeat("0", 63)+"1"), fmt.Sprintf("valid PDF %d", i))
		r.TraceID = fmt.Sprintf("completed-%d", i)
		r.Deadline = now.Add(settlementDeadlineOffset).Unix()
		out := rejected.Handle(context.Background(), r)
		if out.Pass || out.Status != 402 || out.Error != "invalid_payment" {
			t.Fatalf("completed unpaid outcome %d: %+v", i, out)
		}
	}
	for i := range 2 {
		out := recordOutcome(t, service, header, fmt.Sprintf("abandoned-%d", i), protocol.PaymentOutcomeAbandoned)
		if !out.Pass {
			t.Fatalf("abandoned outcome %d: %+v", i, out)
		}
	}
	// A Lambda retry of the same typed event does not consume another slot.
	if out := recordOutcome(t, service, header, "abandoned-1", protocol.PaymentOutcomeAbandoned); !out.Pass {
		t.Fatalf("outcome replay: %+v", out)
	}

	preflight := request(header, "next PDF")
	preflight.VerifyOnly = true
	preflight.Deadline = now.Add(10 * time.Second).Unix()
	out := service.Handle(context.Background(), preflight)
	if out.Pass || out.Status != 429 || out.Error != "unpaid_compute_quota_exceeded" {
		t.Fatalf("combined unpaid outcomes did not block fresh work: %+v", out)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.failures) != 0 || len(store.quotas) != 1 {
		t.Fatalf("outcome accounting poisoned document cache or split rows: failures=%v quotas=%v", store.failures, store.quotas)
	}
	for _, quota := range store.quotas {
		if quota.Unpaid != 3 || quota.Abandoned != 2 || len(quota.Events) != 5 {
			t.Fatalf("typed outcome quota=%+v", quota)
		}
	}
}

func TestDisconnectedLambdaDefinitiveFailureUsesStableSettlementWindow(t *testing.T) {
	boundary := time.Now().Truncate(FailedParseWindow).Add(FailedParseWindow)
	now := boundary.Add(-time.Second)
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: rejectingFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	header := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Minute).Unix(), boundary.Add(2*time.Minute).Unix())
	r := request(header, "completed valid PDF")
	r.TraceID = "lambda-continues-after-invoke-cancel"
	r.Deadline = boundary.Add(10 * time.Second).Unix() // settlement-stage start is boundary-10s

	// Cancelling Invoke does not cancel the Lambda runtime context. Model those
	// as distinct contexts and let the private invocation finish after its caller
	// has gone away.
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	cancelCaller()
	if callerCtx.Err() == nil {
		t.Fatal("caller cancellation fixture failed")
	}
	if out := service.Handle(context.Background(), r); out.Pass || out.Status != 402 || out.Error != "invalid_payment" {
		t.Fatalf("late definitive rejection: %+v", out)
	}
	now = boundary.Add(time.Second)
	if out := service.Handle(context.Background(), r); out.Pass || out.Status != 402 || out.Error != "invalid_payment" {
		t.Fatalf("cross-boundary invocation replay: %+v", out)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.quotas) != 1 {
		t.Fatalf("one invocation created %d hourly rows", len(store.quotas))
	}
	for _, quota := range store.quotas {
		if quota.Unpaid != 1 || quota.Abandoned != 0 || len(quota.Events) != 1 || quota.ExpiresAt != boundary.Unix() {
			t.Fatalf("unstable late-completion quota: %+v", quota)
		}
	}
}

func TestOnlyDefinitiveNormalPaymentRejectionCountsCompletedWork(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	header := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Minute).Unix(), now.Add(2*time.Minute).Unix())
	for _, tc := range []struct {
		name        string
		operation   string
		facilitator Facilitator
		wantStatus  int
	}{
		{name: "preflight rejection", operation: "verify", facilitator: rejectingFacilitator{}, wantStatus: 402},
		{name: "provider failure", operation: "normal", facilitator: &countingFacilitator{err: errors.New("provider unavailable")}, wantStatus: 502},
		{name: "expired invocation", operation: "expired", facilitator: rejectingFacilitator{}, wantStatus: 504},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{}
			service := Service{Store: store, Facilitator: tc.facilitator, Resource: testResource, Now: func() time.Time { return now }}
			r := request(header, "valid PDF")
			r.TraceID = "excluded-" + tc.name
			r.Deadline = now.Add(settlementDeadlineOffset).Unix()
			if tc.operation == "verify" {
				r.VerifyOnly = true
				r.Deadline = now.Add(10 * time.Second).Unix()
			} else if tc.operation == "expired" {
				r.Deadline = now.Unix()
			}
			out := service.Handle(context.Background(), r)
			if out.Pass || out.Status != tc.wantStatus {
				t.Fatalf("response=%+v", out)
			}
			store.mu.Lock()
			defer store.mu.Unlock()
			if len(store.quotas) != 0 {
				t.Fatalf("non-definitive or preflight failure consumed quota: %+v", store.quotas)
			}
		})
	}
}

func TestPaidBindingUsesOnlyAbandonmentQuotaWithoutClaimingRetry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	header := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Minute).Unix(), now.Add(3*time.Minute).Unix())
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	original := request(header, "paid PDF")
	original.Deadline = now.Add(protocol.RequestTimeout).Unix()
	if out := service.Handle(context.Background(), original); !out.Pass {
		t.Fatalf("initial payment: %+v", out)
	}
	for i := range FailedParseQuota {
		if out := recordOutcome(t, service, header, fmt.Sprintf("paid-abandon-%d", i), protocol.PaymentOutcomeAbandoned); !out.Pass {
			t.Fatalf("paid abandonment %d: %+v", i, out)
		}
	}
	preflight := original
	preflight.VerifyOnly = true
	preflight.Deadline = now.Add(10 * time.Second).Unix()
	out := service.Handle(context.Background(), preflight)
	if out.Pass || out.Status != 429 || out.Error != "request_abandonment_quota_exceeded" {
		t.Fatalf("paid abandonment quota not enforced: %+v", out)
	}
	// Authorization and signature bytes for a settled EIP-3009 transfer can be
	// recovered from public calldata. Replaying that public receipt must affect
	// only this binding, never the payer's independent purchases or receipts.
	independentHeader := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Minute).Unix(), now.Add(3*time.Minute).Unix())
	independent := request(independentHeader, "independent paid PDF")
	independent.Deadline = now.Add(protocol.RequestTimeout).Unix()
	independentPreflight := independent
	independentPreflight.VerifyOnly = true
	independentPreflight.Deadline = now.Add(10 * time.Second).Unix()
	if out := service.Handle(context.Background(), independentPreflight); !out.Pass {
		t.Fatalf("public receipt poisoned independent preflight: %+v", out)
	}
	if out := service.Handle(context.Background(), independent); !out.Pass {
		t.Fatalf("public receipt poisoned independent purchase: %+v", out)
	}
	independent.VerifyOnly = true
	independent.Deadline = now.Add(10 * time.Second).Unix()
	if out := service.Handle(context.Background(), independent); !out.Pass {
		t.Fatalf("public receipt poisoned other paid binding: %+v", out)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.rows) != 2 || len(store.quotas) != 1 {
		t.Fatalf("binding-scoped abandonment state: rows=%d quotas=%+v", len(store.rows), store.quotas)
	}
	for _, binding := range store.rows {
		if binding.RetryCount != 0 {
			t.Fatalf("abandonment claimed a paid retry: %+v", binding)
		}
	}
	for _, quota := range store.quotas {
		if quota.Unpaid != 0 || quota.Abandoned != FailedParseQuota {
			t.Fatalf("paid abandonment quota=%+v", quota)
		}
	}
}

func TestPaidFailureQuotaKeysAreBindingScopedAndPrivate(t *testing.T) {
	cfg := protocol.Config{}
	payer := "0x" + strings.Repeat("ab", 20)
	paymentOne := protocol.SHA256([]byte("payment one"))
	paymentTwo := protocol.SHA256([]byte("payment two"))
	walletKey, walletExpiry := failureQuotaKey(cfg, payer, 1000)
	paidOne, paidExpiry := paidFailureQuotaKey(cfg, payer, paymentOne, 1000)
	paidTwo, otherExpiry := paidFailureQuotaKey(cfg, payer, paymentTwo, 1000)
	if walletExpiry != paidExpiry || paidExpiry != otherExpiry || walletKey == paidOne || paidOne == paidTwo {
		t.Fatalf("quota scopes collided: wallet=%q paid1=%q paid2=%q", walletKey, paidOne, paidTwo)
	}
	for _, key := range []string{walletKey, paidOne, paidTwo} {
		if strings.Contains(strings.ToLower(key), strings.TrimPrefix(strings.ToLower(payer), "0x")) || strings.Contains(key, paymentOne) || strings.Contains(key, paymentTwo) {
			t.Fatalf("quota key disclosed payer or payment identity: %q", key)
		}
	}
}

func TestFreshAuthorizationMustCoverAdmittedComputeBudget(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	privateKey := strings.Repeat("0", 63) + "1"

	for _, tc := range []struct {
		name       string
		operation  string
		remaining  time.Duration
		wantPass   bool
		wantVerify int32
	}{
		{name: "normal official authorization", operation: "verify", remaining: 180 * time.Second, wantPass: true, wantVerify: 1},
		{name: "deliberately two second preflight", operation: "verify", remaining: 2 * time.Second},
		{name: "preflight one second short", operation: "verify", remaining: protocol.RequestTimeout - time.Second},
		{name: "preflight exact request budget", operation: "verify", remaining: protocol.RequestTimeout, wantPass: true, wantVerify: 1},
		{name: "parse one second short", operation: "check", remaining: protocol.MinimumParseBudget - time.Second},
		{name: "parse exact minimum budget", operation: "check", remaining: protocol.MinimumParseBudget, wantPass: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := signedWithValidity(t, privateKey, now.Add(-time.Second).Unix(), now.Add(tc.remaining).Unix())
			facilitator := &countingFacilitator{}
			service := Service{Store: &memoryStore{}, Facilitator: facilitator, Resource: testResource, Now: func() time.Time { return now }}
			r := request(header, "valid PDF")
			switch tc.operation {
			case "verify":
				r.VerifyOnly = true
				r.Deadline = now.Add(10 * time.Second).Unix()
			case "check":
				r.CheckDocument = true
				r.Deadline = now.Add(5 * time.Second).Unix()
			}
			out := service.Handle(context.Background(), r)
			if out.Pass != tc.wantPass || !tc.wantPass && (out.Status != 402 || out.Error != "invalid_payment") {
				t.Fatalf("fresh authorization budget result: %+v", out)
			}
			if facilitator.verifyCalls.Load() != tc.wantVerify || facilitator.calls.Load() != 0 {
				t.Fatalf("provider calls verify=%d settle=%d", facilitator.verifyCalls.Load(), facilitator.calls.Load())
			}
		})
	}
}

func TestConfirmedPaidRetryBypassesFreshAuthorizationBudget(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	header := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Second).Unix(), now.Add(120*time.Second).Unix())
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	original := request(header, "paid document")
	original.Deadline = now.Add(protocol.RequestTimeout).Unix()
	if out := service.Handle(context.Background(), original); !out.Pass {
		t.Fatalf("initial payment: %+v", out)
	}

	now = now.Add(121 * time.Second)
	preflight := original
	preflight.VerifyOnly = true
	preflight.Deadline = now.Add(10 * time.Second).Unix()
	if out := service.Handle(context.Background(), preflight); !out.Pass || out.Settlement != nil {
		t.Fatalf("paid preflight required fresh authorization: %+v", out)
	}
	retry := original
	retry.CheckDocument = true
	retry.Deadline = now.Add(5 * time.Second).Unix()
	if out := service.Handle(context.Background(), retry); !out.Pass || out.Settlement != nil {
		t.Fatalf("paid document retry required fresh authorization: %+v", out)
	}
}

func TestExpiredPreflightAuthorizationCanRecordRecentCompletedFailure(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	header := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Second).Unix(), now.Add(protocol.RequestTimeout).Unix())
	store := &memoryStore{}
	facilitator := &countingFacilitator{}
	service := Service{Store: store, Facilitator: facilitator, Resource: testResource, Now: func() time.Time { return now }}
	preflight := request(header, "slow bad PDF")
	preflight.Deadline = now.Add(protocol.RequestTimeout).Unix()
	preflight.VerifyOnly = true
	if out := service.Handle(context.Background(), preflight); !out.Pass {
		t.Fatalf("preflight: %+v", out)
	}

	// The parser completed just after the authorization expired. This is
	// historical failure attribution only; it never reaches settlement.
	now = now.Add(protocol.RequestTimeout + time.Second)
	failed := preflight
	failed.VerifyOnly = false
	failed.DocumentFailed = true
	failed.Deadline = now.Add(5 * time.Second).Unix()
	failed.TraceID = "server-generated-failure-event"
	if out := service.Handle(context.Background(), failed); !out.Pass || out.Settlement != nil {
		t.Fatalf("recent expired failure not recorded: %+v", out)
	}
	if facilitator.verifyCalls.Load() != 1 || facilitator.calls.Load() != 0 {
		t.Fatalf("failure attribution reached provider: verify=%d settle=%d", facilitator.verifyCalls.Load(), facilitator.calls.Load())
	}
	// Replaying the same internal Lambda event is idempotent.
	if out := service.Handle(context.Background(), failed); !out.Pass {
		t.Fatalf("failure replay: %+v", out)
	}
	store.mu.Lock()
	var count int64
	for _, row := range store.quotas {
		count += row.Unpaid
	}
	store.mu.Unlock()
	if count != 1 {
		t.Fatalf("replayed failure count=%d", count)
	}

	// A valid historical signature is not an unlimited failure-recording
	// credential after the server's maximum parse duration has passed.
	now = time.Unix(mustInt64(t, authorizationValidBefore(t, header)), 0).Add(documentFailureAttributionLifetime + time.Second)
	tooOld := failed
	tooOld.BodySHA256 = protocol.SHA256([]byte("another PDF"))
	tooOld.Deadline = now.Add(5 * time.Second).Unix()
	if out := service.Handle(context.Background(), tooOld); out.Pass || out.Status != 402 {
		t.Fatalf("stale failure attribution accepted: %+v", out)
	}
}

func TestDocumentFailureReplayUsesStableWindowAcrossBoundary(t *testing.T) {
	boundary := time.Now().Truncate(FailedParseWindow).Add(FailedParseWindow)
	now := boundary.Add(-time.Second)
	header := signedWithValidity(t, strings.Repeat("0", 63)+"1", now.Add(-time.Minute).Unix(), boundary.Add(time.Minute).Unix())
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	r := request(header, "boundary failure")
	r.DocumentFailed = true
	r.TraceID = "stable-cross-window-event"
	r.Deadline = boundary.Add(4 * time.Second).Unix() // callback time is boundary-1s
	if out := service.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("first failure event: %+v", out)
	}
	now = boundary.Add(time.Second)
	if out := service.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("cross-window replay: %+v", out)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.quotas) != 1 {
		t.Fatalf("one failure event created %d window rows", len(store.quotas))
	}
	for _, row := range store.quotas {
		if row.Unpaid != 1 || len(row.Events) != 1 {
			t.Fatalf("cross-window replay was counted twice: %+v", row)
		}
	}
}

func TestDocumentFailureRejectsUnstableFutureDeadline(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	r := request(signed(t), "bad PDF")
	r.DocumentFailed = true
	r.Deadline = now.Add(documentFailureDeadlineLead + time.Second).Unix()
	if out := service.Handle(context.Background(), r); out.Pass || out.Status != 400 {
		t.Fatalf("distant failure deadline accepted: %+v", out)
	}
	if len(store.failures) != 0 || len(store.quotas) != 0 {
		t.Fatal("invalid failure deadline reached metadata store")
	}
}

func authorizationValidBefore(t *testing.T, header string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var payload types.PaymentPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	nested, _ := json.Marshal(payload.Payload)
	var exact evm.ExactEIP3009Payload
	if err := json.Unmarshal(nested, &exact); err != nil {
		t.Fatal(err)
	}
	return exact.Authorization.ValidBefore
}

func mustInt64(t *testing.T, value string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

type cancelOnFailureCacheWrite struct {
	*memoryStore
	cancel context.CancelFunc
}

func (s cancelOnFailureCacheWrite) MarkFailed(ctx context.Context, hash string, now int64) error {
	err := s.memoryStore.MarkFailed(ctx, hash, now)
	s.cancel()
	return err
}

func TestCompletedFailureBookkeepingSurvivesCallerCancellation(t *testing.T) {
	base := &memoryStore{}
	ctx, cancel := context.WithCancel(context.Background())
	store := cancelOnFailureCacheWrite{memoryStore: base, cancel: cancel}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource}
	r := request(signed(t), "bad PDF completed before disconnect")
	r.DocumentFailed = true
	r.Deadline = time.Now().Add(documentFailureDeadlineOffset).Unix()
	r.TraceID = "completed-before-disconnect"
	out := service.Handle(ctx, r)
	if out.Pass || out.Status != 504 {
		t.Fatalf("cancelled caller received output: %+v", out)
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.failures) != 1 || len(base.quotas) != 1 {
		t.Fatalf("completed failure bookkeeping lost after cancellation: failures=%d quotas=%d", len(base.failures), len(base.quotas))
	}
}

func TestFailedParseQuotaSharedByWalletAndIsolatedBetweenWallets(t *testing.T) {
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource}
	recordFailedParses(t, service, strings.Repeat("0", 63)+"1", int(FailedParseQuota))

	blocked := request(signed(t), "new PDF")
	blocked.VerifyOnly = true
	out := service.Handle(context.Background(), blocked)
	if out.Pass || out.Status != 429 || out.Error != "unpaid_compute_quota_exceeded" || out.RetryAfter < 1 || out.RetryAfter > int64(FailedParseWindow/time.Second) || out.Settlement != nil {
		t.Fatalf("same wallet bypassed quota: %+v", out)
	}
	other := request(signedWithKey(t, secondTestPrivateKey), "other wallet PDF")
	other.VerifyOnly = true
	if out := service.Handle(context.Background(), other); !out.Pass || out.RetryAfter != 0 {
		t.Fatalf("other wallet inherited quota: %+v", out)
	}

	payer := headerPayer(t, blocked.Header)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.quotas) != 1 {
		t.Fatalf("quota rows=%d", len(store.quotas))
	}
	for key, row := range store.quotas {
		if !strings.HasPrefix(key, failedParseQuotaNamespace) || strings.Contains(strings.ToLower(key), payer) || row.Unpaid != FailedParseQuota {
			t.Fatalf("quota row contains identity or wrong count: key=%q row=%+v", key, row)
		}
	}
}

func TestSuccessfulPaymentsDoNotConsumeFailedParseQuota(t *testing.T) {
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource}
	for i := range FailedParseQuota + 1 {
		if out := service.Handle(context.Background(), request(signed(t), fmt.Sprintf("successful PDF %d", i))); !out.Pass {
			t.Fatalf("successful payment %d: %+v", i, out)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.quotas) != 0 {
		t.Fatalf("successful parses consumed quota: %+v", store.quotas)
	}
}

func TestConfirmedPaidRetryBypassesFailedParseQuota(t *testing.T) {
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource}
	header := signed(t)
	original := request(header, "paid document")
	if out := service.Handle(context.Background(), original); !out.Pass {
		t.Fatalf("initial payment: %+v", out)
	}
	recordFailedParses(t, service, strings.Repeat("0", 63)+"1", int(FailedParseQuota))

	preflight := original
	preflight.VerifyOnly = true
	if out := service.Handle(context.Background(), preflight); !out.Pass || out.RetryAfter != 0 {
		t.Fatalf("paid preflight blocked by failure quota: %+v", out)
	}
	retry := original
	retry.CheckDocument = true
	if out := service.Handle(context.Background(), retry); !out.Pass || out.RetryAfter != 0 {
		t.Fatalf("paid retry blocked by failure quota: %+v", out)
	}
}

func TestKnownFailureAndPreflightRacesDoNotMiscountQuota(t *testing.T) {
	store := &memoryStore{}
	service := Service{Store: store, Facilitator: &countingFacilitator{}, Resource: testResource}
	key := strings.Repeat("0", 63) + "1"
	badBody := "known failed PDF"
	failed := request(signedWithKey(t, key), badBody)
	failed.DocumentFailed = true
	failed.Deadline = time.Now().Add(documentFailureDeadlineOffset).Unix()
	if out := service.Handle(context.Background(), failed); !out.Pass {
		t.Fatal(out)
	}
	for range 2 {
		known := request(signedWithKey(t, key), badBody)
		known.CheckDocument = true
		if out := service.Handle(context.Background(), known); out.Status != 422 {
			t.Fatalf("known failure not rejected: %+v", out)
		}
	}

	// Four more failures reach the threshold. A request that preflighted before
	// the fifth one is rechecked before a fresh document is admitted to parsing.
	preflighted := request(signedWithKey(t, key), "fresh document")
	preflighted.VerifyOnly = true
	if out := service.Handle(context.Background(), preflighted); !out.Pass {
		t.Fatalf("early preflight: %+v", out)
	}
	recordFailedParses(t, service, key, int(FailedParseQuota-1))
	preflighted.VerifyOnly = false
	preflighted.CheckDocument = true
	if out := service.Handle(context.Background(), preflighted); out.Status != 429 || out.Error != "unpaid_compute_quota_exceeded" {
		t.Fatalf("document recheck missed quota: %+v", out)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	var total int64
	for _, row := range store.quotas {
		total += row.Unpaid
	}
	if total != FailedParseQuota {
		t.Fatalf("known-cache rejection changed failure count: %d", total)
	}
}

type malformedQuotaStore struct {
	*memoryStore
	count, abandoned, expiry int64
	err                      error
}

func (s malformedQuotaStore) GetFailureQuota(context.Context, string, int64) (FailureQuota, error) {
	return FailureQuota{Unpaid: s.count, Abandonments: s.abandoned, ExpiresAt: s.expiry}, s.err
}

func TestFailureQuotaWindowExpiryAndMalformedRows(t *testing.T) {
	cfg := protocol.Config{}
	payer := "0x" + strings.Repeat("ab", 20)
	before, end := failureQuotaKey(cfg, payer, 3599)
	after, nextEnd := failureQuotaKey(cfg, payer, 3600)
	if before == after || end != 3600 || nextEnd != 7200 {
		t.Fatalf("fixed-window keys: before=%q after=%q ends=%d/%d", before, after, end, nextEnd)
	}

	now := time.Now().Truncate(time.Second)
	header := signed(t)
	actualPayer := headerPayer(t, header)
	key, _ := failureQuotaKey(cfg, actualPayer, now.Unix())
	expired := &memoryStore{quotas: map[string]failureQuotaRecord{key: {Unpaid: FailedParseQuota, ExpiresAt: now.Unix()}}}
	service := Service{Store: expired, Facilitator: &countingFacilitator{}, Resource: testResource, Now: func() time.Time { return now }}
	r := request(header, "new window")
	r.Deadline = now.Add(time.Minute).Unix()
	r.VerifyOnly = true
	if out := service.Handle(context.Background(), r); !out.Pass {
		t.Fatalf("expired asynchronous TTL row enforced: %+v", out)
	}

	_, expectedExpiry := failureQuotaKey(cfg, actualPayer, now.Unix())
	for _, malformed := range []malformedQuotaStore{
		{memoryStore: &memoryStore{}, count: -1, expiry: expectedExpiry},
		{memoryStore: &memoryStore{}, count: 1, expiry: expectedExpiry + 1},
		{memoryStore: &memoryStore{}, count: maxFailedParseEvents + 1, expiry: expectedExpiry},
		{memoryStore: &memoryStore{}, count: 1, abandoned: maxFailedParseEvents, expiry: expectedExpiry},
		{memoryStore: &memoryStore{}, err: errors.New("malformed counter")},
	} {
		service.Store = malformed
		if out := service.Handle(context.Background(), r); out.Pass || out.Status != 502 || out.RetryAfter != 0 {
			t.Fatalf("malformed quota failed open: %+v", out)
		}
	}
}

func TestDynamoFailureQuotaUsesStrongReadAndAtomicAdd(t *testing.T) {
	const payerCanary = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	key, expiresAt := failureQuotaKey(protocol.Config{}, payerCanary, 1000)
	var mu sync.Mutex
	var unpaid, abandoned int64
	seen := map[string]struct{}{}
	lostEventID := protocol.SHA256([]byte("event-0"))
	lostResponse := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		raw, _ := json.Marshal(body)
		if strings.Contains(strings.ToLower(string(raw)), payerCanary) {
			t.Error("raw payer reached DynamoDB")
		}
		if body["TableName"] != "metadata" {
			t.Error("wrong table")
		}
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.UpdateItem":
			if body["UpdateExpression"] != "SET #kind = if_not_exists(#kind, :kind), expiresAt = if_not_exists(expiresAt, :expires) ADD #count :one, #events :events" {
				t.Error("failure counter is not atomic ADD")
			}
			if body["ConditionExpression"] != "attribute_not_exists(paymentKey) OR (#kind = :kind AND expiresAt = :expires AND attribute_exists(#events) AND size(#events) < :eventCap AND NOT contains(#events, :event))" {
				t.Error("quota update is not kind/window/idempotency bound")
			}
			values := body["ExpressionAttributeValues"].(map[string]any)
			names := body["ExpressionAttributeNames"].(map[string]any)
			countName, _ := names["#count"].(string)
			if countName != "failureCount" && countName != "abandonmentCount" {
				t.Error("unknown typed quota counter")
			}
			eventValues := values[":events"].(map[string]any)["SS"].([]any)
			eventID := eventValues[0].(string)
			mu.Lock()
			if _, duplicate := seen[eventID]; duplicate {
				mu.Unlock()
				w.Header().Set("Content-Type", "application/x-amz-json-1.0")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"duplicate"}`))
				return
			}
			seen[eventID] = struct{}{}
			if countName == "abandonmentCount" {
				abandoned++
			} else {
				unpaid++
			}
			loseThisResponse := eventID == lostEventID && !lostResponse
			if loseThisResponse {
				lostResponse = true
			}
			mu.Unlock()
			if loseThisResponse {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case "DynamoDB_20120810.GetItem":
			if body["ConsistentRead"] != true {
				t.Error("eventual quota read")
			}
			mu.Lock()
			currentUnpaid, currentAbandoned := unpaid, abandoned
			events := make([]string, 0, len(seen))
			for eventID := range seen {
				events = append(events, eventID)
			}
			mu.Unlock()
			item := map[string]any{
				"kind": map[string]string{"S": failedParseQuotaKind}, "failureCount": map[string]string{"N": strconv.FormatInt(currentUnpaid, 10)}, "expiresAt": map[string]string{"N": strconv.FormatInt(expiresAt, 10)}, "failureEvents": map[string]any{"SS": events},
			}
			if currentAbandoned > 0 {
				item["abandonmentCount"] = map[string]string{"N": strconv.FormatInt(currentAbandoned, 10)}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Item": item})
		default:
			t.Error("unexpected DynamoDB operation")
		}
	}))
	defer ts.Close()
	awsCfg := aws.Config{Region: "us-east-2", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture"}, nil
	})}
	store := DynamoStore{Client: dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ts.URL); o.RetryMaxAttempts = 1 }), Table: "metadata"}
	// The write commits but its HTTP response is lost. A strong read of the
	// event set must reconcile success without issuing another ADD.
	if err := store.IncrementFailureQuota(context.Background(), key, expiresAt, lostEventID, quotaEventUnpaid); err != nil {
		t.Fatal("lost response reconciliation", err)
	}
	var wg sync.WaitGroup
	for i := 1; i < 31; i++ {
		wg.Add(1)
		go func(event int) {
			defer wg.Done()
			if err := store.IncrementFailureQuota(context.Background(), key, expiresAt, protocol.SHA256([]byte(fmt.Sprintf("event-%d", event))), quotaEventUnpaid); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if err := store.IncrementFailureQuota(context.Background(), key, expiresAt, protocol.SHA256([]byte("abandoned-event")), quotaEventAbandoned); err != nil {
		t.Fatal("typed abandonment update", err)
	}
	if err := store.IncrementFailureQuota(context.Background(), key, expiresAt, lostEventID, quotaEventUnpaid); err != nil {
		t.Fatal("idempotent replay", err)
	}
	got, err := store.GetFailureQuota(context.Background(), key, 1000)
	if err != nil || got.Unpaid != 31 || got.Abandonments != 1 || got.ExpiresAt != expiresAt {
		t.Fatalf("atomic quota=%+v err=%v", got, err)
	}
}
