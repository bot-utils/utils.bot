package telemetry

import (
	"context"
	"log/slog"
	"time"
)

// Request has fixed operational categories and an explicit request-target
// diagnostic. Only RequestURL may emit the target, after bounded credential
// redaction. Headers, body contents and requester network metadata are excluded.
type Request struct {
	Route, Method                                             string
	RequestPath, RequestQuery                                 string
	ForceQuery                                                bool
	Stage, Code                                               string
	RecoveredPanic                                            bool
	VerifyMS, UploadMS, CheckMS, ParseMS, PrepareMS, SettleMS int64
	PDFium, Poppler                                           string
	NoncanonicalQuery, NoncanonicalPath                       bool
}

func (r *Request) Step(stage string) func() {
	r.Stage = stage
	start := time.Now()
	return func() {
		elapsed := Milliseconds(start)
		switch stage {
		case "verify":
			r.VerifyMS = elapsed
		case "upload":
			r.UploadMS = elapsed
		case "document_check":
			r.CheckMS = elapsed
		case "parse":
			r.ParseMS = elapsed
		case "prepare":
			r.PrepareMS = elapsed
		case "settle":
			r.SettleMS = elapsed
		}
	}
}
func (r *Request) Attempt(engine, outcome string) {
	outcome = parserOutcome(outcome)
	switch engine {
	case "pdfium":
		r.PDFium = outcome
	case "poppler":
		r.Poppler = outcome
	}
}
func parserOutcome(outcome string) string {
	switch outcome {
	case "", "success", "document_error", "password_required", "timeout", "output_limit", "service_error", "setup_failed", "invalid_output", "cancelled":
	default:
		outcome = "unknown"
	}
	return outcome
}
func RequestDetailSummary(ctx context.Context, status int, writeFailed, settled, fallback bool, started time.Time, r Request) {
	serviceFailure := status >= 500 || writeFailed
	toolRequest := (r.Route == "/v1/pdf/text" || r.Route == "/v1/html/markdown") && r.Method == "POST"
	quoteIssued := toolRequest && status == 402 && r.Stage == "headers" && r.Code == ""
	// The payment service can definitively reject an authorization after upload
	// or parsing. Require its fixed rejection codes and a payment stage; a status
	// alone must not turn a provider failure or uncertain settlement into rejection.
	paymentStage := r.Stage == "verify" || r.Stage == "document_check" || r.Stage == "settle"
	definitivePaymentRejection := status == 402 && paymentStage && (r.Code == "invalid_payment" || r.Code == "payment_amount_mismatch")
	paymentRejected := toolRequest && (definitivePaymentRejection || (r.Stage == "verify" && (status == 400 || status == 409 || status == 422)) || (status == 400 && (r.Code == "invalid_payment_header" || r.Code == "ambiguous_content_headers")))
	outcome := "other"
	switch {
	case paymentRejected:
		outcome = "payment_rejected"
	case quoteIssued:
		outcome = "quote_issued"
	case status == 200 && toolRequest && !writeFailed:
		outcome = "completed"
	case status == 422:
		outcome = "document_failure"
	case status == 429:
		outcome = "capacity_refusal"
	case serviceFailure:
		outcome = "service_failure"
	case status >= 400:
		outcome = "request_rejected"
	}
	stage := r.Stage
	switch stage {
	case "headers", "verify", "upload", "document_check", "parse", "prepare", "settle", "write":
	default:
		stage = "unknown"
	}
	fields := []any{"telemetry", "summary", "role", "server", "schema", 6, "route", AccessRoute(r.Route), "method", AccessMethod(r.Method), "request_id", Trace(ctx), "status", status, "outcome", outcome, "code", Code(r.Code), "stage", stage, "panic_recovered", r.RecoveredPanic, "elapsed_ms", Milliseconds(started),
		"verify_ms", r.VerifyMS, "upload_ms", r.UploadMS, "check_ms", r.CheckMS, "parse_ms", r.ParseMS, "prepare_ms", r.PrepareMS, "settle_ms", r.SettleMS, "pdfium", parserOutcome(r.PDFium), "poppler", parserOutcome(r.Poppler),
		"requests", 1, "tool_requests", Count(toolRequest), "quotes_issued", Count(quoteIssued), "payment_rejections", Count(paymentRejected), "completed", Count(toolRequest && status == 200 && !writeFailed), "document_failures", Count(status == 422), "service_failures", Count(serviceFailure), "paid_service_failures", Count(settled && serviceFailure), "capacity_refusals", Count(status == 429), "fallback_attempts", Count(fallback), "write_failed", writeFailed}
	if status == 400 && r.Code == "noncanonical_request_url" {
		fields = append(fields, "query_present", r.NoncanonicalQuery, "encoded_path", r.NoncanonicalPath)
	}
	if r.RequestPath != "" && (AccessRoute(r.Route) == "unsupported" || r.RequestPath != r.Route || r.RequestQuery != "" || r.ForceQuery) {
		target, truncated, redacted := RequestURL(r.RequestPath, r.RequestQuery, r.ForceQuery)
		fields = append(fields, "request_url", target, "request_url_truncated", truncated, "request_url_redacted", redacted)
	}
	slog.InfoContext(ctx, "request summary", fields...)
}
