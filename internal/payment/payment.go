package payment

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
	"pdfservice/internal/telemetry"
)

const RetryLifetime = 5 * time.Minute
const MaxPaidRetries int64 = 3
const documentFailureAttributionLifetime = 120 * time.Second
const documentFailureWriteTimeout = 3 * time.Second
const documentFailureDeadlineLead = 6 * time.Second
const documentFailureDeadlineOffset = 5 * time.Second
const settlementDeadlineOffset = 20 * time.Second

const preparedState = "prepared"
const paidState = "paid"

type Binding struct {
	State              string
	ReservationID      string
	RetryCount         int64
	PaymentKey         string
	BodySHA256         string
	BodyLength         int64
	PaymentProofSHA256 string
	Transaction        string
	RetryUntil         int64
	ExpiresAt          int64
}

var ErrConflict = errors.New("binding already exists")
var ErrRetryLimit = errors.New("paid retry unavailable")

type Store interface {
	Get(context.Context, string) (*Binding, error)
	Put(context.Context, Binding) error
	Complete(context.Context, Binding) error
	ClaimRetry(context.Context, Binding, int64) error
}
type Facilitator interface {
	Verify(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (bool, error)
	Settle(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (*x402.SettleResponse, error)
}

type Service struct {
	Config      protocol.Config
	Store       Store
	Facilitator Facilitator
	Resource    string
	Now         func() time.Time
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func fail(status int, code string) protocol.PaymentResponse {
	return protocol.PaymentResponse{Status: status, Error: code}
}

func (s Service) Handle(ctx context.Context, r protocol.PaymentRequest) (out protocol.PaymentResponse) {
	started := time.Now()
	stats := telemetry.Payment{Operation: "settle"}
	switch {
	case r.VerifyOnly:
		stats.Operation = "verify"
	case r.CheckDocument:
		stats.Operation = "document_check"
	case r.DocumentFailed:
		stats.Operation = "record_failure"
	case r.RecordOutcome != "":
		stats.Operation = "record_outcome"
	}
	ctx = telemetry.WithTrace(ctx, r.TraceID)
	defer func() {
		// The Lambda runtime logs uncaught panic values/stacks. They can originate
		// in providers/libraries, so contain them without emitting raw diagnostics.
		// A service failure never proves that no settlement happened: retain the
		// normal binding/reconciliation behavior and never retry a transfer here.
		if recover() != nil {
			out = fail(502, "payment_unavailable")
			stats.HandlerPanic = true
		}
		stats.Status = out.Status
		if out.Pass {
			stats.Status = 200
		}
		stats.Code = out.Error
		telemetry.PaymentSummary(ctx, stats, started)
	}()

	actions := 0
	for _, selected := range []bool{r.VerifyOnly, r.CheckDocument, r.DocumentFailed, r.RecordOutcome != ""} {
		if selected {
			actions++
		}
	}
	if actions > 1 || r.RecordOutcome != "" && r.RecordOutcome != protocol.PaymentOutcomeAbandoned {
		return fail(400, "invalid_payment_operation")
	}
	now := s.now()
	cfg := s.Config
	if ctx.Err() != nil {
		return fail(504, "request_deadline")
	}
	if r.Deadline <= now.Unix() {
		return fail(504, "request_deadline")
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(r.Deadline, 0))
	defer cancel()
	requiresDocument := !r.VerifyOnly && r.RecordOutcome != protocol.PaymentOutcomeAbandoned
	if requiresDocument && (r.BodyLength <= 0 || r.BodyLength > protocol.MaxPDF || !hexBytes(r.BodySHA256, 32, false)) {
		return fail(400, "invalid_document_metadata")
	}
	if r.RecordOutcome == protocol.PaymentOutcomeAbandoned && (r.BodyLength != 0 || r.BodySHA256 != "") {
		return fail(400, "invalid_document_metadata")
	}
	p, a, err := decodePayload(r.Header, s.Resource, now, cfg, true)
	if err != nil {
		return fail(402, "invalid_payment")
	}
	// Preflight and abandonment can authenticate either supported price before
	// any complete upload exists. Every document operation must independently
	// bind the exact authorized price to the receiver's actual uploaded length.
	if requiresDocument && p.Accepted.Amount != cfg.ForSize(r.BodyLength).Requirements().Amount {
		return fail(402, "payment_amount_mismatch")
	}
	if p.Accepted.Amount == protocol.LargeAmount {
		cfg = cfg.ForSize(protocol.MaxPDF)
	}
	if (r.DocumentFailed || r.RecordOutcome != "") && (r.Deadline <= int64(documentFailureDeadlineOffset/time.Second) || r.Deadline-now.Unix() > int64(documentFailureDeadlineLead/time.Second)) {
		return fail(400, "invalid_payment_operation")
	}
	identity := strings.Join([]string{cfg.Network(), strings.ToLower(cfg.Asset()), strings.ToLower(a.Authorization.From), strings.ToLower(a.Authorization.Nonce)}, "|")
	// Real settlements must never reuse synthetic mock bindings.
	if cfg.Mode() != protocol.ModeMock {
		identity = cfg.Mode() + "|" + identity
	}
	key := protocol.SHA256([]byte(identity))
	// Canonical typed fields and signature bytes: header whitespace/order is irrelevant.
	a.Authorization.From = strings.ToLower(a.Authorization.From)
	a.Authorization.To = strings.ToLower(a.Authorization.To)
	a.Authorization.Nonce = strings.ToLower(a.Authorization.Nonce)
	a.Signature = strings.ToLower(a.Signature)
	proofJSON, _ := json.Marshal(a)
	proof := protocol.SHA256(proofJSON)
	// A normal operation runs only after the server has parsed a complete
	// document. If this invocation definitively rejects payment, account for
	// that completed unpaid work before returning. The Lambda runtime continues
	// this bounded write even when its Invoke caller has disconnected.
	if actions == 0 {
		defer func() {
			if out.Pass || out.Status != 402 || out.Error != "invalid_payment" {
				return
			}
			valid, verifyErr := verifyEOAAuthorization(context.WithoutCancel(ctx), cfg, a)
			if verifyErr != nil || !valid {
				return
			}
			attributedAt := r.Deadline - int64(settlementDeadlineOffset/time.Second)
			if attributedAt <= 0 {
				out = fail(502, "payment_store_unavailable")
				return
			}
			writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), documentFailureWriteTimeout)
			defer writeCancel()
			if writeErr := s.incrementFailureQuota(writeCtx, cfg, a.Authorization.From, attributedAt, failureQuotaEventID(r, proof, quotaEventUnpaid), quotaEventUnpaid); writeErr != nil {
				out = fail(502, "payment_store_unavailable")
			}
		}()
	}
	b, err := s.Store.Get(ctx, key)
	if err != nil {
		stats.BindingFailures = 1
		return fail(502, "payment_store_unavailable")
	}
	now = s.now()
	if ctx.Err() != nil || now.Unix() >= r.Deadline {
		return fail(504, "request_deadline")
	}
	if r.RecordOutcome != "" {
		return s.recordAbandonmentOutcome(ctx, r, cfg, a, proof, key, b, now)
	}
	if b != nil {
		if !r.VerifyOnly && !r.CheckDocument && !r.DocumentFailed {
			defer func() { stats.PaidRetries = telemetry.Count(out.Pass) }()
		}
		if r.CheckDocument || r.DocumentFailed {
			approved := matchWithConfig(cfg, *b, r, proof, now.Unix(), a.Authorization.From)
			if approved.Pass && r.CheckDocument {
				if quota := s.checkFailureQuota(ctx, cfg, a.Authorization.From, key); !quota.Pass {
					return quota
				}
				if err := s.Store.ClaimRetry(ctx, *b, now.Unix()); err != nil {
					if errors.Is(err, ErrRetryLimit) {
						return fail(429, "retry_limit_reached")
					}
					stats.BindingFailures = 1
					return fail(502, "payment_store_unavailable")
				}
				if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
					return fail(504, "request_deadline")
				}
				if s.now().Unix() >= b.RetryUntil {
					return fail(409, "retry_window_expired")
				}
			}
			approved.Settlement = nil
			return approved
		}
		if r.VerifyOnly {
			// A settled authorization can be eligible for a same-file retry even
			// when its onchain nonce is already consumed. Preflight checks the
			// stored proof/window; actual request bytes are checked after upload.
			approved := matchWithConfig(cfg, *b, protocol.PaymentRequest{BodySHA256: b.BodySHA256, BodyLength: b.BodyLength}, proof, now.Unix(), a.Authorization.From)
			if approved.Pass && b.RetryCount >= MaxPaidRetries {
				return fail(429, "retry_limit_reached")
			}
			if approved.Pass {
				if quota := s.checkFailureQuota(ctx, cfg, a.Authorization.From, key); !quota.Pass {
					return quota
				}
			}
			approved.Settlement = nil
			return approved
		}
		return matchWithConfig(cfg, *b, r, proof, now.Unix(), a.Authorization.From)
	}
	validBefore, _ := strconv.ParseInt(a.Authorization.ValidBefore, 10, 64)
	if now.Unix() >= validBefore && !r.DocumentFailed {
		return fail(402, "invalid_payment")
	}
	remainingAuthorization := time.Duration(validBefore-now.Unix()) * time.Second
	// Fresh authorizations must cover the work they admit. Otherwise a caller
	// can repeatedly submit deliberately short-lived authorizations that pass
	// preflight, expire during successful parsing, and are never settled or
	// counted by the failed-document quota. Confirmed paid retries returned
	// above are intentionally independent of the old spend authorization.
	if r.VerifyOnly && remainingAuthorization < protocol.RequestTimeout {
		return fail(402, "invalid_payment")
	}
	if r.CheckDocument && remainingAuthorization < protocol.MinimumParseBudget {
		return fail(402, "invalid_payment")
	}
	if r.CheckDocument || r.DocumentFailed {
		documents, ok := s.Store.(DocumentStore)
		if !ok {
			return fail(502, "document_cache_unavailable")
		}
		if r.DocumentFailed {
			// The server reports this only after a preflighted parse has completed
			// with a cacheable document error. At that point the short-lived spend
			// authorization may have expired, so authenticate the historical EOA
			// signature locally instead of asking the facilitator to approve a new
			// spend. Keep attribution bounded to the maximum request lifetime plus
			// a small bookkeeping margin.
			if now.Unix()-validBefore > int64(documentFailureAttributionLifetime/time.Second) {
				return fail(402, "invalid_payment")
			}
			valid, err := verifyEOAAuthorization(ctx, cfg, a)
			if err != nil {
				return fail(402, "invalid_payment")
			}
			if !valid {
				stats.VerifyRejected = 1
				return fail(402, "invalid_payment")
			}
			failureTime := s.now().Unix()
			// Once a completed parser failure is authenticated, persist its cache
			// and quota bookkeeping even if the HTTP caller disconnects or the
			// request deadline expires between these two writes. This context is
			// detached from caller cancellation but remains tightly bounded.
			writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), documentFailureWriteTimeout)
			defer writeCancel()
			if err := documents.MarkFailed(writeCtx, r.BodySHA256, failureTime); err != nil {
				return fail(502, "document_cache_unavailable")
			}
			// The server gives failure bookkeeping a fresh five-second deadline.
			// Use its derived callback time for a stable fixed-window key, so the
			// same Lambda event cannot count in two windows if replay straddles a
			// boundary.
			attributedAt := r.Deadline - int64(documentFailureDeadlineOffset/time.Second)
			if err := s.incrementFailureQuota(writeCtx, cfg, a.Authorization.From, attributedAt, failureQuotaEventID(r, proof, quotaEventUnpaid), quotaEventUnpaid); err != nil {
				return fail(502, "payment_store_unavailable")
			}
			if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
				return fail(504, "request_deadline")
			}
			return protocol.PaymentResponse{Pass: true}
		}
		failed, err := documents.Failed(ctx, r.BodySHA256, now.Unix())
		if err != nil {
			return fail(502, "document_cache_unavailable")
		}
		if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
			return fail(504, "request_deadline")
		}
		if failed {
			return fail(422, "document_known_unparseable")
		}
		if quota := s.checkFailureQuota(ctx, cfg, a.Authorization.From, ""); !quota.Pass {
			return quota
		}
		return protocol.PaymentResponse{Pass: true}
	}
	if r.VerifyOnly {
		stats.VerifyCalls = 1
		valid, err := s.Facilitator.Verify(ctx, p, a)
		if err != nil {
			stats.ProviderFailures = 1
			return fail(502, "payment_unavailable")
		}
		if !valid {
			stats.VerifyRejected = 1
			return fail(402, "invalid_payment")
		}
		validBefore, _ := strconv.ParseInt(a.Authorization.ValidBefore, 10, 64)
		if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
			return fail(504, "request_deadline")
		}
		if s.now().Unix() >= validBefore {
			return fail(402, "invalid_payment")
		}
		if quota := s.checkFailureQuota(ctx, cfg, a.Authorization.From, ""); !quota.Pass {
			return quota
		}
		// Only metadata is read. No settlement or new binding is performed.
		return protocol.PaymentResponse{Pass: true}
	}
	// Recheck the signature before creating a reservation. A caller with a
	// well-shaped but forged authorization must never claim another payer's nonce.
	stats.VerifyCalls = 1
	valid, verifyErr := s.Facilitator.Verify(ctx, p, a)
	if verifyErr != nil {
		stats.ProviderFailures = 1
		return fail(502, "payment_unavailable")
	}
	if !valid {
		stats.VerifyRejected = 1
		return fail(402, "invalid_payment")
	}
	if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
		return fail(504, "request_deadline")
	}
	if s.now().Unix() >= validBefore {
		return fail(402, "invalid_payment")
	}
	reservation := make([]byte, 16)
	if _, err := rand.Read(reservation); err != nil {
		return fail(502, "payment_store_unavailable")
	}
	b = &Binding{State: preparedState, ReservationID: hex.EncodeToString(reservation), PaymentKey: key,
		BodySHA256: r.BodySHA256, BodyLength: r.BodyLength, PaymentProofSHA256: proof,
		RetryUntil: s.now().Unix() + int64(RetryLifetime/time.Second), ExpiresAt: s.now().Unix() + 30*24*3600}
	if err := s.Store.Put(ctx, *b); err != nil {
		existing, readErr := s.Store.Get(ctx, key)
		if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
			return fail(504, "request_deadline")
		}
		if readErr != nil || existing == nil {
			stats.BindingFailures = 1
			return fail(502, "payment_store_unavailable")
		}
		// A lost reply to OUR reservation is recoverable. Another invocation's
		// reservation must not trigger a second settlement.
		if existing.ReservationID != b.ReservationID {
			approved := matchWithConfig(cfg, *existing, r, proof, s.now().Unix(), a.Authorization.From)
			if !approved.Pass {
				return approved
			}
			// Another replica completed this same authorization between our
			// consistent read and conditional reservation. Count this already-parsed
			// request against the paid retry budget before releasing its output.
			if err := s.Store.ClaimRetry(ctx, *existing, s.now().Unix()); err != nil {
				if errors.Is(err, ErrRetryLimit) {
					return fail(429, "retry_limit_reached")
				}
				stats.BindingFailures = 1
				return fail(502, "payment_store_unavailable")
			}
			stats.PaidRetries = 1
			if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
				return fail(504, "request_deadline")
			}
			return approved
		}
		if existing.State != preparedState || existing.Transaction != "" || existing.BodySHA256 != b.BodySHA256 || existing.BodyLength != b.BodyLength || existing.PaymentProofSHA256 != proof || existing.RetryUntil != b.RetryUntil || existing.ExpiresAt != b.ExpiresAt {
			stats.BindingFailures = 1
			return fail(502, "payment_store_unavailable")
		}
	}
	if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
		return fail(504, "request_deadline")
	}
	if s.now().Unix() >= validBefore {
		return fail(503, "payment_confirmation_unavailable")
	}
	stats.SettlementAttempts = 1
	settled, err := s.Facilitator.Settle(ctx, p, a)
	if err != nil {
		stats.ProviderFailures = 1
		return fail(502, "payment_unavailable")
	}
	if settled == nil {
		stats.ProviderFailures = 1
		return fail(502, "payment_unavailable")
	}
	if pending := pendingSettlement(cfg, settled, a.Authorization.From); pending != nil {
		// Current x402 exact-EVM facilitators reconcile an already-broadcast
		// transaction when the resource server retries settle exactly once with
		// the identical payload and requirements. Never retry an unstructured
		// timeout or a pending response that cannot be bound to this payer.
		if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
			out := fail(502, "payment_unavailable")
			out.Settlement = pending
			return out
		}
		stats.SettlementAttempts = 2
		reconciled, retryErr := s.Facilitator.Settle(ctx, p, a)
		if retryErr != nil || reconciled == nil {
			stats.ProviderFailures = 1
			out := fail(502, "payment_unavailable")
			out.Settlement = pending
			return out
		}
		if !reconciled.Success {
			next := pendingSettlement(cfg, reconciled, a.Authorization.From)
			if next == nil || !strings.EqualFold(next.Transaction, pending.Transaction) {
				next = pending
			}
			stats.ProviderFailures = 1
			out := fail(502, "payment_unavailable")
			out.Settlement = next
			return out
		}
		if !cfg.ValidSettlement(reconciled) || !strings.EqualFold(reconciled.Payer, a.Authorization.From) {
			stats.ProviderFailures = 1
			out := fail(502, "invalid_settlement_response")
			out.Settlement = pending
			return out
		}
		settled = reconciled
	}
	if !settled.Success {
		if settled.ErrorReason == "settlement_pending" || settled.Transaction != "" {
			stats.ProviderFailures = 1
			out := fail(502, "payment_unavailable")
			out.Settlement = cfg.SettlementEvidence(settled)
			return out
		}
		return fail(402, "invalid_payment")
	}
	if !cfg.ValidSettlement(settled) || !strings.EqualFold(settled.Payer, a.Authorization.From) {
		stats.ProviderFailures = 1
		return fail(502, "invalid_settlement_response")
	}
	settled = cfg.SettlementEvidence(settled)
	stats.SettlementConfirmed = 1
	// Persist an authoritative confirmation even if the HTTP deadline has just
	// elapsed. This bounded bookkeeping cannot authorize another transfer or
	// release output to a cancelled caller.
	boundAt := s.now()
	b.State, b.Transaction = paidState, settled.Transaction
	b.RetryUntil = boundAt.Unix() + int64(RetryLifetime/time.Second)
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	err = s.Store.Complete(saveCtx, *b)
	if err != nil {
		existing, readErr := s.Store.Get(saveCtx, key)
		if readErr != nil || existing == nil || existing.State != paidState || existing.Transaction != b.Transaction || existing.ReservationID != b.ReservationID || existing.BodySHA256 != b.BodySHA256 || existing.BodyLength != b.BodyLength || existing.PaymentProofSHA256 != proof {
			saveCancel()
			stats.BindingFailures = 1
			out := fail(502, "payment_store_unavailable")
			out.Settlement = settled
			return out
		}
	}
	saveCancel()
	stats.BindingCreated = 1
	if ctx.Err() != nil || s.now().Unix() >= min(b.RetryUntil, r.Deadline) {
		out := fail(504, "payment_unavailable")
		out.Settlement = settled
		return out
	}
	return protocol.PaymentResponse{Pass: true, Settlement: settled}
}

// recordAbandonmentOutcome attributes abandoned work without granting spend
// authority or consuming a paid retry. The callback authenticates the original
// EIP-3009 signer locally and writes only hashed, fixed-window quota metadata.
func (s Service) recordAbandonmentOutcome(ctx context.Context, r protocol.PaymentRequest, cfg protocol.Config, a evm.ExactEIP3009Payload, proof, paymentKey string, b *Binding, now time.Time) protocol.PaymentResponse {
	validBefore, _ := strconv.ParseInt(a.Authorization.ValidBefore, 10, 64)
	paidBinding := b != nil && (b.State == paidState || b.State == "" && b.Transaction != "")
	if !paidBinding && now.Unix()-validBefore > int64(documentFailureAttributionLifetime/time.Second) {
		return fail(402, "invalid_payment")
	}
	valid, err := verifyEOAAuthorization(ctx, cfg, a)
	if err != nil || !valid {
		return fail(402, "invalid_payment")
	}

	if b != nil {
		matchRequest := r
		if r.RecordOutcome == protocol.PaymentOutcomeAbandoned {
			matchRequest.BodySHA256 = b.BodySHA256
			matchRequest.BodyLength = b.BodyLength
		}
		matched := matchWithConfig(cfg, *b, matchRequest, proof, now.Unix(), a.Authorization.From)
		if !matched.Pass && (matched.Status != 503 || matched.Error != "payment_confirmation_unavailable") {
			matched.Settlement = nil
			return matched
		}
	}

	eventType := quotaEventAbandoned
	attributedAt := r.Deadline - int64(documentFailureDeadlineOffset/time.Second)
	if attributedAt <= 0 {
		return fail(400, "invalid_payment_operation")
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), documentFailureWriteTimeout)
	defer cancel()
	eventID := failureQuotaEventID(r, proof, eventType)
	if paidBinding {
		err = s.incrementPaidAbandonmentQuota(writeCtx, cfg, a.Authorization.From, paymentKey, attributedAt, eventID)
	} else {
		err = s.incrementFailureQuota(writeCtx, cfg, a.Authorization.From, attributedAt, eventID, eventType)
	}
	if err != nil {
		return fail(502, "payment_store_unavailable")
	}
	if ctx.Err() != nil || s.now().Unix() >= r.Deadline {
		return fail(504, "request_deadline")
	}
	return protocol.PaymentResponse{Pass: true}
}

func pendingSettlement(cfg protocol.Config, settled *x402.SettleResponse, payer string) *x402.SettleResponse {
	evidence := cfg.SettlementEvidence(settled)
	if evidence == nil || evidence.Success || evidence.ErrorReason != "settlement_pending" || !strings.EqualFold(evidence.Payer, payer) {
		return nil
	}
	return evidence
}

func match(b Binding, r protocol.PaymentRequest, proof string, now int64, payer string) protocol.PaymentResponse {
	return matchWithConfig(protocol.Config{}, b, r, proof, now, payer)
}

func matchWithConfig(cfg protocol.Config, b Binding, r protocol.PaymentRequest, proof string, now int64, payer string) protocol.PaymentResponse {
	if !hexBytes(b.BodySHA256, 32, false) || b.BodyLength <= 0 || b.BodyLength > protocol.MaxPDF || b.RetryUntil <= 0 || b.ExpiresAt < b.RetryUntil || b.RetryCount < 0 || b.RetryCount > MaxPaidRetries || !hexBytes(b.PaymentProofSHA256, 32, false) {
		return fail(502, "payment_store_unavailable")
	}
	if b.PaymentProofSHA256 != proof {
		return fail(402, "invalid_payment")
	}
	if b.BodySHA256 != r.BodySHA256 || b.BodyLength != r.BodyLength {
		return fail(409, "payment_document_mismatch")
	}
	if b.State != "" && !hexBytes(b.ReservationID, 16, false) {
		return fail(502, "payment_store_unavailable")
	}
	if b.State == preparedState {
		if b.Transaction != "" {
			return fail(502, "payment_store_unavailable")
		}
		return fail(503, "payment_confirmation_unavailable")
	}
	if b.State != "" && b.State != paidState {
		return fail(502, "payment_store_unavailable")
	}
	if now >= b.RetryUntil {
		return fail(409, "retry_window_expired")
	}
	if !hexBytes(b.Transaction, 32, true) {
		return fail(502, "payment_store_unavailable")
	}
	return protocol.PaymentResponse{Pass: true, Settlement: &x402.SettleResponse{Success: true, Transaction: b.Transaction, Network: x402.Network(cfg.Network()), Payer: payer}}
}

func decode(header, resource string, now time.Time) (types.PaymentPayload, evm.ExactEIP3009Payload, error) {
	return decodeWithConfig(header, resource, now, protocol.Config{})
}
func decodeWithConfig(header, resource string, now time.Time, cfg protocol.Config) (types.PaymentPayload, evm.ExactEIP3009Payload, error) {
	return decodePayload(header, resource, now, cfg, false)
}

// Expired spend authorizations are usable only when the service finds a matching
// confirmed binding. New payments still require an unexpired authorization.
func decodePayload(header, resource string, now time.Time, cfg protocol.Config, allowExpired bool) (types.PaymentPayload, evm.ExactEIP3009Payload, error) {
	var p types.PaymentPayload
	var a evm.ExactEIP3009Payload
	bad := func() (types.PaymentPayload, evm.ExactEIP3009Payload, error) {
		return p, a, errors.New("invalid payment")
	}
	if len(header) == 0 || len(header) > protocol.MaxPaymentHeader {
		return bad()
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(header)
	if err != nil {
		return bad()
	}
	if err = jsonwire.Unmarshal(raw, &p, protocol.MaxPaymentHeader); err != nil || p.X402Version != 2 {
		return bad()
	}
	got := p.Accepted
	switch got.Amount {
	case protocol.SmallAmount:
		cfg = cfg.ForSize(0)
	case protocol.LargeAmount:
		cfg = cfg.ForSize(protocol.MaxPDF)
	default:
		return bad()
	}
	want := cfg.Requirements()
	if got.Scheme != want.Scheme || got.Network != want.Network || !strings.EqualFold(got.Asset, want.Asset) || !strings.EqualFold(got.PayTo, want.PayTo) || got.Amount != want.Amount || got.MaxTimeoutSeconds != want.MaxTimeoutSeconds {
		return bad()
	}
	if got.Extra["name"] != want.Extra["name"] || got.Extra["version"] != "2" || got.Extra["assetTransferMethod"] != "eip3009" || got.Extra["paymentFlow"] != want.Extra["paymentFlow"] {
		return bad()
	}
	if p.Resource == nil || p.Resource.URL != resource {
		return bad()
	}
	b, err := json.Marshal(p.Payload)
	if err != nil || jsonwire.Decode(b, &a, protocol.MaxPaymentHeader) != nil {
		return bad()
	}
	if !hexBytes(a.Authorization.From, 20, true) || !hexBytes(a.Authorization.To, 20, true) || !hexBytes(a.Authorization.Nonce, 32, true) || !hexBytes(a.Signature, 65, true) {
		return bad()
	}
	if !strings.EqualFold(a.Authorization.To, want.PayTo) || a.Authorization.Value != want.Amount {
		return bad()
	}
	after, e1 := strconv.ParseInt(a.Authorization.ValidAfter, 10, 64)
	before, e2 := strconv.ParseInt(a.Authorization.ValidBefore, 10, 64)
	if e1 != nil || e2 != nil || after < 0 || before <= 0 || (!allowExpired && before <= now.Unix()) || before > now.Unix()+180 || after >= now.Unix() || after >= before {
		return bad()
	}
	if strconv.FormatInt(after, 10) != a.Authorization.ValidAfter || strconv.FormatInt(before, 10) != a.Authorization.ValidBefore {
		return bad()
	}
	// Optional descriptions, extras and extensions are not signed payment
	// fields. Give the facilitator only the quote this service issued and the
	// exact typed EIP-3009 payload, never the caller's generic metadata maps.
	quote := cfg.Quote(resource)
	p.Accepted, p.Resource, p.Extensions = quote.Accepts[0], quote.Resource, quote.Extensions
	p.Payload = map[string]interface{}{
		"signature": a.Signature,
		"authorization": map[string]interface{}{
			"from": a.Authorization.From, "to": a.Authorization.To, "value": a.Authorization.Value,
			"validAfter": a.Authorization.ValidAfter, "validBefore": a.Authorization.ValidBefore, "nonce": a.Authorization.Nonce,
		},
	}
	return p, a, nil
}

func hexBytes(s string, n int, prefix bool) bool {
	if prefix {
		if !strings.HasPrefix(s, "0x") {
			return false
		}
		s = s[2:]
	}
	if len(s) != 2*n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func verifyEOAAuthorization(ctx context.Context, cfg protocol.Config, a evm.ExactEIP3009Payload) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	const networkPrefix = "eip155:"
	network := cfg.Network()
	if !strings.HasPrefix(network, networkPrefix) {
		return false, errors.New("invalid EVM network")
	}
	chainID, ok := new(big.Int).SetString(strings.TrimPrefix(network, networkPrefix), 10)
	if !ok || chainID.Sign() <= 0 {
		return false, errors.New("invalid EVM chain ID")
	}
	hash, err := evm.HashEIP3009Authorization(a.Authorization, chainID, cfg.Asset(), cfg.TokenName(), "2")
	if err != nil {
		return false, err
	}
	signature, err := hex.DecodeString(strings.TrimPrefix(a.Signature, "0x"))
	if err != nil {
		return false, err
	}
	valid, signatureErr := evm.VerifyEOASignature(hash, signature, common.HexToAddress(a.Authorization.From))
	// Invalid signature encodings/recovery are client rejection, not an
	// infrastructure error.
	if signatureErr != nil {
		return false, nil
	}
	return valid, nil
}

// MockFacilitator is selected only for the fixed local/test mock configuration.
// It verifies real testnet EIP-712 signatures, but performs no RPC, balance check,
// transaction submission or real Coinbase call. Its transaction IDs are synthetic.
type MockFacilitator struct{}

func (MockFacilitator) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	return verifyEOAAuthorization(ctx, protocol.Config{}, a)
}

func (m MockFacilitator) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	valid, err := m.Verify(ctx, p, a)
	if err != nil {
		return nil, err
	}
	if !valid {
		return &x402.SettleResponse{Success: false}, nil
	}
	key := protocol.SHA256([]byte(fmt.Sprintf("mock|%s|%s", strings.ToLower(a.Authorization.From), strings.ToLower(a.Authorization.Nonce))))
	return &x402.SettleResponse{Success: true, Network: protocol.Network, Payer: a.Authorization.From, Transaction: "0x" + key}, nil
}
