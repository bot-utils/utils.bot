package payment

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"pdfservice/internal/protocol"
)

const FailedParseQuota int64 = 5
const FailedParseWindow = protocol.FailedParseWindow
const maxFailedParseEvents int64 = 32

const failedParseQuotaKind = "failed_parse_quota"
const failedParseQuotaNamespace = "failure-quota:"
const quotaEventUnpaid = "unpaid"
const quotaEventAbandoned = "abandoned"

type FailureQuota struct {
	Unpaid       int64
	Abandonments int64
	ExpiresAt    int64
}

type FailureQuotaStore interface {
	GetFailureQuota(context.Context, string, int64) (FailureQuota, error)
	IncrementFailureQuota(context.Context, string, int64, string, string) error
}

func failureQuotaKey(cfg protocol.Config, payer string, now int64) (string, int64) {
	seconds := int64(FailedParseWindow / time.Second)
	windowStart := now - now%seconds
	expiresAt := windowStart + seconds
	identity := strings.Join([]string{
		"failed-parse-quota-v2", cfg.Mode(), cfg.Network(), strings.ToLower(cfg.Asset()), strings.ToLower(payer), strconv.FormatInt(windowStart, 10),
	}, "|")
	return failedParseQuotaNamespace + protocol.SHA256([]byte(identity)), expiresAt
}

func paidFailureQuotaKey(cfg protocol.Config, payer, paymentKey string, now int64) (string, int64) {
	seconds := int64(FailedParseWindow / time.Second)
	windowStart := now - now%seconds
	expiresAt := windowStart + seconds
	identity := strings.Join([]string{
		"failed-parse-quota-v2", "paid-binding", cfg.Mode(), cfg.Network(), strings.ToLower(cfg.Asset()), strings.ToLower(payer), paymentKey, strconv.FormatInt(windowStart, 10),
	}, "|")
	return failedParseQuotaNamespace + protocol.SHA256([]byte(identity)), expiresAt
}

func (s Service) checkFailureQuota(ctx context.Context, cfg protocol.Config, payer, paidPaymentKey string) protocol.PaymentResponse {
	store, ok := s.Store.(FailureQuotaStore)
	if !ok {
		return fail(502, "payment_store_unavailable")
	}
	now := s.now().Unix()
	key, expectedExpiry := failureQuotaKey(cfg, payer, now)
	paidBinding := paidPaymentKey != ""
	if paidBinding {
		key, expectedExpiry = paidFailureQuotaKey(cfg, payer, paidPaymentKey, now)
	}
	quota, err := store.GetFailureQuota(ctx, key, now)
	total := quota.Unpaid + quota.Abandonments
	if err != nil || quota.Unpaid < 0 || quota.Abandonments < 0 || quota.Unpaid > maxFailedParseEvents || quota.Abandonments > maxFailedParseEvents || total < 0 || total > maxFailedParseEvents || total > 0 && quota.ExpiresAt != expectedExpiry {
		return fail(502, "payment_store_unavailable")
	}
	if paidBinding && quota.Abandonments < FailedParseQuota || !paidBinding && total < FailedParseQuota {
		return protocol.PaymentResponse{Pass: true}
	}
	retryAfter := expectedExpiry - now
	if retryAfter < 1 || retryAfter > int64(FailedParseWindow/time.Second) {
		return fail(502, "payment_store_unavailable")
	}
	errorCode := "unpaid_compute_quota_exceeded"
	if paidBinding {
		errorCode = "request_abandonment_quota_exceeded"
	}
	return protocol.PaymentResponse{Status: 429, Error: errorCode, RetryAfter: retryAfter}
}

func failureQuotaEventID(r protocol.PaymentRequest, paymentProof, eventType string) string {
	identity := strings.Join([]string{"resource-outcome-event-v2", eventType, "trace", r.TraceID}, "|")
	if r.TraceID == "" {
		// Direct unit callers do not have the server-generated random request ID.
		// The canonical proof and document hash still make replay deterministic.
		identity = strings.Join([]string{"resource-outcome-event-v2", eventType, "fallback", r.BodySHA256, paymentProof}, "|")
	}
	return protocol.SHA256([]byte(identity))
}

func (s Service) incrementFailureQuota(ctx context.Context, cfg protocol.Config, payer string, attributedAt int64, eventID, eventType string) error {
	store, ok := s.Store.(FailureQuotaStore)
	if !ok {
		return errors.New("failure quota store unavailable")
	}
	key, expiresAt := failureQuotaKey(cfg, payer, attributedAt)
	return store.IncrementFailureQuota(ctx, key, expiresAt, eventID, eventType)
}

func (s Service) incrementPaidAbandonmentQuota(ctx context.Context, cfg protocol.Config, payer, paymentKey string, attributedAt int64, eventID string) error {
	store, ok := s.Store.(FailureQuotaStore)
	if !ok {
		return errors.New("failure quota store unavailable")
	}
	key, expiresAt := paidFailureQuotaKey(cfg, payer, paymentKey, attributedAt)
	return store.IncrementFailureQuota(ctx, key, expiresAt, eventID, quotaEventAbandoned)
}
