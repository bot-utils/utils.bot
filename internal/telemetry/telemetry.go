// Package telemetry emits fixed, small operational records; never customer data.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"
)

type traceKey struct{}

func NewTrace() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func WithTrace(ctx context.Context, id string) context.Context {
	if len(id) != 32 {
		return ctx
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ctx
	}
	return context.WithValue(ctx, traceKey{}, id)
}
func Trace(ctx context.Context) string { id, _ := ctx.Value(traceKey{}).(string); return id }
func Count(b bool) int {
	if b {
		return 1
	}
	return 0
}
func Milliseconds(start time.Time) int64 {
	return min(max(time.Since(start).Milliseconds(), 0), 120000)
}

// One fixed summary per receiver request / Lambda invocation. No dimensions
// contain identifiers. Emit synchronous terminal records so Lambda freeze or a
// quiet endpoint cannot strand counters in a background buffer.
type Payment struct {
	VerifyCalls, VerifyRejected, ProviderFailures, SettlementAttempts, SettlementConfirmed, BindingFailures, PaidRetries, BindingCreated int
	HandlerPanic                                                                                                                         bool
	Operation                                                                                                                            string
	Status                                                                                                                               int
	Code                                                                                                                                 string
}

func PaymentSummary(ctx context.Context, p Payment, started time.Time) {
	slog.InfoContext(ctx, "payment summary", "telemetry", "summary", "role", "payment", "schema", 2, "operation", paymentOperation(p.Operation), "handler_panic", p.HandlerPanic, "request_id", Trace(ctx), "status", p.Status, "code", Code(p.Code), "elapsed_ms", Milliseconds(started),
		"verify_calls", p.VerifyCalls, "verify_rejected", p.VerifyRejected, "provider_failures", p.ProviderFailures, "settlement_attempts", p.SettlementAttempts, "settlement_confirmed", p.SettlementConfirmed, "binding_failures", p.BindingFailures, "paid_retries", p.PaidRetries, "binding_created", p.BindingCreated)
}
func RequestSummary(ctx context.Context, status int, writeFailed, settled, fallback bool, started time.Time) {
	serviceFailure := status >= 500 || writeFailed
	slog.InfoContext(ctx, "request summary", "telemetry", "summary", "role", "server", "request_id", Trace(ctx), "status", status, "elapsed_ms", Milliseconds(started),
		"requests", 1, "completed", Count(status == 200 && !writeFailed), "document_failures", Count(status == 422), "service_failures", Count(serviceFailure), "paid_service_failures", Count(settled && serviceFailure), "capacity_refusals", Count(status == 429), "fallback_attempts", Count(fallback), "write_failed", writeFailed)
}

// Detailed diagnostics are capped globally per process at five each minute.
// The runtime metrics above remain unsampled and exact for completed handlers.
// No goroutine, external SDK/API or paid trace backend is involved.
type Limiter struct {
	mu    sync.Mutex
	start time.Time
	used  int
}

func (l *Limiter) Allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.start.IsZero() || now.Sub(l.start) >= time.Minute {
		l.start = now
		l.used = 0
	}
	if l.used >= 5 {
		return false
	}
	l.used++
	return true
}

var details Limiter

// HTTPErrorWriter drops net/http's free-form diagnostics, which can contain
// source addresses, request contents and panic stacks. Preserve a rate-limited
// fixed category instead; request summaries still record handler outcomes.
type HTTPErrorWriter struct{}

func (HTTPErrorWriter) Write(p []byte) (int, error) {
	if details.Allow(time.Now()) {
		slog.Warn("HTTP transport diagnostic", "reason", "http_transport_failure")
	}
	return len(p), nil
}

func ProviderDetail(ctx context.Context, operation string, status int, reason string, elapsed int64) {
	if operation != "verify" && operation != "settle" {
		return
	}
	if !details.Allow(time.Now()) {
		return
	}
	slog.WarnContext(ctx, "provider diagnostic", "telemetry", "detail", "role", "payment", "request_id", Trace(ctx), "operation", operation, "http_status", max(min(status, 599), 0), "reason", Reason(reason), "elapsed_ms", max(min(elapsed, 120000), 0))
}
func Code(code string) string {
	switch code {
	case "", "ambiguous_content_headers", "application_pdf_required", "capacity_unavailable", "document_cache_unavailable", "document_known_unparseable", "document_parse_failed", "empty_pdf", "insufficient_request_budget", "invalid_document_metadata", "invalid_payment", "invalid_payment_header", "invalid_payment_operation", "invalid_payment_response", "invalid_settlement_response", "invalid_upload", "known_document_failure", "method_not_allowed", "noncanonical_request_url", "not_found", "payment_amount_mismatch", "payment_confirmation_unavailable", "payment_document_mismatch", "payment_store_unavailable", "payment_unavailable", "pdf_too_large", "quote_failed", "range_not_supported", "request_abandonment_quota_exceeded", "request_deadline", "response_encoding_failed", "retry_limit_reached", "retry_window_expired", "service_draining", "service_error", "unexpected_request_body", "unpaid_compute_quota_exceeded", "unsupported_content_encoding":
		return code
	default:
		return "unknown"
	}
}
func Reason(reason string) string {
	switch reason {
	case "kyt_risk_detected", "invalid_exact_evm_payload_authorization_from_address_kyt", "invalid_exact_evm_payload_authorization_to_address_kyt":
		return "risk_rejected"
	case "request_blocked_by_location", "risk_rejected":
		return reason
	case "insufficient_funds", "invalid_scheme", "invalid_network", "invalid_x402_version", "invalid_payment_requirements", "invalid_payload", "invalid_signature", "invalid_exact_evm_payload_signature", "invalid_exact_evm_payload_authorization_value", "invalid_exact_evm_payload_authorization_value_too_low", "invalid_exact_evm_payload_authorization_valid_after", "invalid_exact_evm_payload_authorization_valid_before", "invalid_exact_evm_payload_authorization_nonce", "invalid_exact_evm_payload_recipient_mismatch", "invalid_exact_evm_payload_signature_address", "invalid_exact_evm_payload_authorization_used", "nonce_already_used", "settlement_pending", "settlement_failed", "invalid_response", "transport_failure", "deadline", "unauthorized", "rate_limited", "billing_required", "upstream_failure":
		return reason
	default:
		return "unknown"
	}
}

func paymentOperation(value string) string {
	switch value {
	case "verify", "document_check", "record_failure", "record_outcome", "settle":
		return value
	default:
		return "unknown"
	}
}
