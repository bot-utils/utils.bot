package telemetry

import (
	"context"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"
)

// Request contains bounded operational categories. RejectedURL is the explicit
// exception: a noncanonical API request's encoded path/query. It is not read
// from headers or bodies, but may contain customer data placed in the query.
type Request struct {
	Route, Method                                             string
	Stage, Code                                               string
	VerifyMS, UploadMS, CheckMS, ParseMS, PrepareMS, SettleMS int64
	PDFium, Poppler                                           string
	RejectedURL                                               string
}

const MaxRejectedURLBytes = 2048

func boundedRejectedURL(value string) (string, bool) {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= MaxRejectedURLBytes {
		return value, false
	}
	value = value[:MaxRejectedURLBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value, true
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
	toolRequest := r.Route == "/v1/pdf/text"
	stage := r.Stage
	switch stage {
	case "headers", "verify", "upload", "document_check", "parse", "prepare", "settle", "write":
	default:
		stage = "unknown"
	}
	fields := []any{"telemetry", "summary", "role", "server", "schema", 4, "route", AccessRoute(r.Route), "method", AccessMethod(r.Method), "request_id", Trace(ctx), "status", status, "code", Code(r.Code), "stage", stage, "elapsed_ms", Milliseconds(started),
		"verify_ms", r.VerifyMS, "upload_ms", r.UploadMS, "check_ms", r.CheckMS, "parse_ms", r.ParseMS, "prepare_ms", r.PrepareMS, "settle_ms", r.SettleMS, "pdfium", parserOutcome(r.PDFium), "poppler", parserOutcome(r.Poppler),
		"requests", 1, "tool_requests", Count(toolRequest), "completed", Count(toolRequest && status == 200 && !writeFailed), "document_failures", Count(status == 422), "service_failures", Count(serviceFailure), "paid_service_failures", Count(settled && serviceFailure), "capacity_refusals", Count(status == 429), "fallback_attempts", Count(fallback), "write_failed", writeFailed}
	if status == 400 && r.Code == "noncanonical_request_url" && r.RejectedURL != "" {
		target, truncated := boundedRejectedURL(r.RejectedURL)
		fields = append(fields, "rejected_url", target, "rejected_url_truncated", truncated)
	}
	slog.InfoContext(ctx, "request summary", fields...)
}
