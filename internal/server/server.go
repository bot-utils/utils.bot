package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"pdfservice/internal/docs"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/parser"
	"pdfservice/internal/paths"
	"pdfservice/internal/protocol"
	"pdfservice/internal/telemetry"
)

type PayFunc func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error)
type ParseFunc func(context.Context, []byte) (parser.Result, error)
type Server struct {
	Config         protocol.Config
	Resource       string
	Pay            PayFunc
	Parse          ParseFunc
	Slots          chan struct{}
	Draining       atomic.Bool
	healthRequests atomic.Uint64
}

type observedWriter struct {
	http.ResponseWriter
	detail                         telemetry.Request
	status                         int
	writeFailed, settled, fallback bool
}

func (w *observedWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *observedWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(data)
	w.writeFailed = w.writeFailed || err != nil || n != len(data)
	return n, err
}
func (w *observedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func New(resource string, pay PayFunc, parse ParseFunc) *Server {
	return NewWithConfig(resource, pay, parse, protocol.Config{})
}
func NewWithConfig(resource string, pay PayFunc, parse ParseFunc, cfg protocol.Config) *Server {
	return &Server{Resource: resource, Pay: pay, Parse: parse, Slots: make(chan struct{}, 1), Config: cfg}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if s.Draining.Load() {
			write(w, 503, map[string]string{"status": "draining"})
			return
		}
		write(w, 200, map[string]string{"status": "ready", "paymentMode": s.Config.Mode()})
	})
	mux.HandleFunc("POST /v1/pdf/text", func(w http.ResponseWriter, r *http.Request) {
		s.pdf(w, r)
	})
	mux.Handle("GET /", docs.NewWithConfig(s.Resource, s.Config))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ALB/container probes have no protected CloudFront-origin header. Keep
		// them quiet; viewer health requests delivered by our protected origin
		// get the same sanitized access record as other requests. This marker
		// classifies telemetry only; ALB rules enforce origin authorization.
		if r.URL.Path == "/health" && r.URL.RawQuery == "" && !r.URL.ForceQuery && r.URL.RawPath == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.Header.Get("X-Agent-Pdf-Origin") == "" {
			s.healthRequests.Add(1)
		} else {
			start := time.Now()
			trace := telemetry.NewTrace()
			r = r.WithContext(telemetry.WithTrace(r.Context(), trace))
			w.Header().Set("X-Request-ID", trace)
			observed := &observedWriter{ResponseWriter: w, detail: telemetry.Request{Route: telemetry.AccessRoute(r.URL.Path), Method: telemetry.AccessMethod(r.Method), Stage: "headers"}}
			defer func() {
				telemetry.RequestDetailSummary(r.Context(), observed.status, observed.writeFailed, observed.settled, observed.fallback, start, observed.detail)
			}()
			w = observed
		}
		w.Header().Set("X-Payment-Mode", s.Config.Mode())
		w.Header().Set("Link", docs.DiscoveryLink)
		if s.Resource == protocol.APIOrigin+"/v1/pdf/text" {
			w.Header().Set("Link", "<"+protocol.SiteOrigin+"/openapi>; rel=\"service-desc\"; type=\"application/yaml\"")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !paths.Supported(r.URL.Path) {
			w.Header().Set("Connection", "close")
			write(w, 404, map[string]string{"error": "not_found"})
			return
		}
		// Repeat admission checks at the origin; correctness must not depend on
		// the CDN being present or on an intermediate proxy normalizing URLs.
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
			if observed, ok := w.(*observedWriter); ok {
				observed.detail.RejectedURL = r.URL.EscapedPath()
				if r.URL.RawQuery != "" || r.URL.ForceQuery {
					observed.detail.RejectedURL += "?" + r.URL.RawQuery
				}
			}
			w.Header().Set("Connection", "close")
			write(w, 400, map[string]string{"error": "noncanonical_request_url"})
			return
		}
		if len(r.Header.Values("Range")) != 0 || len(r.Header.Values("If-Range")) != 0 {
			w.Header().Set("Connection", "close")
			write(w, 400, map[string]string{"error": "range_not_supported"})
			return
		}
		// Refuse unused methods and bodies without draining untrusted uploads.
		if s.regionalCORS(w, r) {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
			w.Header().Set("Connection", "close")
			w.Header().Set("Allow", "GET, HEAD, POST")
			write(w, 405, map[string]string{"error": "method_not_allowed"})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path != "/v1/pdf/text" {
			w.Header().Set("Connection", "close")
			write(w, 404, map[string]string{"error": "not_found"})
			return
		}
		if r.Method != http.MethodPost && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
			w.Header().Set("Connection", "close")
			write(w, 400, map[string]string{"error": "unexpected_request_body"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func write(w http.ResponseWriter, status int, value any) {
	if observed, ok := w.(*observedWriter); ok {
		if errorBody, ok := value.(map[string]string); ok {
			observed.detail.Code = telemetry.Code(errorBody["error"])
		}
	}
	b, err := json.Marshal(value)
	if err != nil || len(b) > protocol.MaxOutput {
		status = 502
		b = []byte(`{"error":"response_encoding_failed"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if w.Header().Get("X-Payment-Mode") == "" {
		w.Header().Set("X-Payment-Mode", protocol.ModeMock)
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
func (s *Server) quote(w http.ResponseWriter, code string, size ...int64) {
	if observed, ok := w.(*observedWriter); ok {
		observed.detail.Code = telemetry.Code(code)
	}
	cfg := s.Config
	if len(size) != 0 {
		cfg = cfg.ForSize(size[0])
	}
	q := cfg.Quote(s.Resource)
	q.Error = code
	header, err := protocol.Header(q)
	if err != nil {
		write(w, 502, map[string]string{"error": "quote_failed"})
		return
	}
	w.Header().Set("PAYMENT-REQUIRED", header)
	w.Header().Set("Connection", "close")
	write(w, 402, q)
}

func (s *Server) rejectPayment(w http.ResponseWriter, paid protocol.PaymentResponse, size ...int64) {
	if !validPaymentBackoff(paid) {
		write(w, 502, map[string]string{"error": "invalid_payment_response"})
		return
	}
	if paid.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(paid.RetryAfter, 10))
	}
	switch paid.Status {
	case 402:
		s.quote(w, paid.Error, size...)
	case 400, 409, 422, 429, 502, 503, 504:
		write(w, paid.Status, map[string]string{"error": paid.Error})
	default:
		write(w, 502, map[string]string{"error": "invalid_payment_response"})
	}
}

func validPaymentBackoff(p protocol.PaymentResponse) bool {
	if p.Error == "unpaid_compute_quota_exceeded" || p.Error == "request_abandonment_quota_exceeded" {
		return !p.Pass && p.Status == 429 && p.RetryAfter >= 1 && p.RetryAfter <= int64(protocol.FailedParseWindow/time.Second) && p.Settlement == nil
	}
	return p.RetryAfter == 0
}

func (s *Server) recordAbandonment(ctx context.Context, header string) bool {
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	deadline, _ := recordCtx.Deadline()
	request := protocol.PaymentRequest{
		TraceID:       telemetry.Trace(ctx),
		Header:        header,
		Deadline:      deadline.Unix(),
		RecordOutcome: protocol.PaymentOutcomeAbandoned,
	}
	recorded, err := s.Pay(recordCtx, request)
	if err != nil || !recorded.Pass || recorded.Status != 0 || recorded.Error != "" || recorded.Settlement != nil || !validPaymentBackoff(recorded) {
		slog.ErrorContext(ctx, "resource outcome write failed", "outcome", protocol.PaymentOutcomeAbandoned, "request_id", telemetry.Trace(ctx))
		return false
	}
	return true
}

func (s *Server) pdf(w http.ResponseWriter, r *http.Request) {
	detail := &telemetry.Request{Route: telemetry.AccessRoute(r.URL.Path), Method: telemetry.AccessMethod(r.Method), Stage: "headers"}
	if observed, ok := w.(*observedWriter); ok {
		detail = &observed.detail
	}
	timedPay := func(stage string, ctx context.Context, p protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		done := detail.Step(stage)
		defer done()
		return s.Pay(ctx, p)
	}
	// Every early refusal must flush without waiting for an unconsumed body.
	w.Header().Set("Connection", "close")
	// Local cleanup happens on every path; the standard net/http server also isolates handler panics.
	defer func() {
		if recover() != nil {
			slog.Error("request failed", "reason", "handler_panic", "request_id", telemetry.Trace(r.Context()))
			write(w, 502, map[string]string{"error": "service_error"})
		}
	}()
	if s.Draining.Load() {
		write(w, 503, map[string]string{"error": "service_draining"})
		return
	}
	h := r.Header.Values("PAYMENT-SIGNATURE")
	if len(h) == 0 {
		s.quote(w, "", r.ContentLength)
		return
	}
	if len(h) != 1 || len(h[0]) == 0 || len(h[0]) > protocol.MaxPaymentHeader {
		write(w, 400, map[string]string{"error": "invalid_payment_header"})
		return
	}
	if len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) > 1 {
		write(w, 400, map[string]string{"error": "ambiguous_content_headers"})
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/pdf" {
		write(w, 415, map[string]string{"error": "application_pdf_required"})
		return
	}
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		write(w, 415, map[string]string{"error": "unsupported_content_encoding"})
		return
	}
	if r.ContentLength > protocol.MaxPDF {
		write(w, 413, map[string]string{"error": "pdf_too_large"})
		return
	}
	select {
	case s.Slots <- struct{}{}:
		defer func() { <-s.Slots }()
	default:
		w.Header().Set("Retry-After", "1")
		write(w, 429, map[string]string{"error": "capacity_unavailable"})
		return
	}
	deadline := time.Now().Add(protocol.RequestTimeout)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	if ctx.Err() != nil {
		write(w, 504, map[string]string{"error": "request_deadline"})
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(45 * time.Second))
	_ = controller.SetWriteDeadline(deadline)
	verifyCtx, verifyCancel := context.WithTimeout(ctx, 10*time.Second)
	verified, err := timedPay("verify", verifyCtx, protocol.PaymentRequest{TraceID: telemetry.Trace(ctx), Header: h[0], Deadline: deadline.Unix(), VerifyOnly: true})
	verifyExpired := verifyCtx.Err() != nil
	verifyCancel()
	if verifyExpired {
		write(w, 504, map[string]string{"error": "request_deadline"})
		return
	}
	if err != nil {
		w.Header().Set("Connection", "close")
		write(w, 502, map[string]string{"error": "payment_unavailable"})
		return
	}
	if !validPaymentBackoff(verified) || verified.Pass && (verified.Status != 0 || verified.Error != "" || verified.Settlement != nil) {
		write(w, 502, map[string]string{"error": "invalid_payment_response"})
		return
	}
	if !verified.Pass {
		w.Header().Set("Connection", "close")
		s.rejectPayment(w, verified, r.ContentLength)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxPDF)
	defer r.Body.Close()
	uploadDone := detail.Step("upload")
	body, err := io.ReadAll(r.Body)
	uploadDone()
	if err != nil {
		s.recordAbandonment(ctx, h[0])
		var large *http.MaxBytesError
		status := 400
		code := "invalid_upload"
		if errors.As(err, &large) {
			status = 413
			code = "pdf_too_large"
		}
		write(w, status, map[string]string{"error": code})
		return
	}
	if len(body) == 0 {
		write(w, 400, map[string]string{"error": "empty_pdf"})
		return
	}
	w.Header().Del("Connection")
	_ = controller.SetReadDeadline(deadline)
	if time.Until(deadline) < protocol.MinimumParseBudget {
		s.recordAbandonment(ctx, h[0])
		write(w, 503, map[string]string{"error": "insufficient_request_budget"})
		return
	}
	hash := protocol.SHA256(body)
	// The private Lambda performs direct document-cache and paid-body binding
	// lookups. The receiver and native workers gain no DynamoDB permissions.
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	checked, checkErr := timedPay("document_check", checkCtx, protocol.PaymentRequest{TraceID: telemetry.Trace(ctx), Header: h[0], BodySHA256: hash, BodyLength: int64(len(body)), Deadline: deadline.Unix(), CheckDocument: true})
	checkExpired := checkCtx.Err() != nil
	checkCancel()
	if checkExpired || ctx.Err() != nil {
		if r.Context().Err() != nil {
			s.recordAbandonment(ctx, h[0])
		}
		write(w, 504, map[string]string{"error": "request_deadline"})
		return
	}
	if checkErr != nil {
		write(w, 502, map[string]string{"error": "document_cache_unavailable"})
		return
	}
	if !validPaymentBackoff(checked) || checked.Pass && (checked.Status != 0 || checked.Error != "" || checked.Settlement != nil) {
		write(w, 502, map[string]string{"error": "invalid_payment_response"})
		return
	}
	if !checked.Pass {
		s.rejectPayment(w, checked, int64(len(body)))
		return
	}
	parseDone := detail.Step("parse")
	result, err := s.Parse(ctx, body)
	parseDone()
	for _, attempt := range result.Attempts {
		detail.Attempt(attempt.Engine, attempt.Outcome)
	}
	if observed, ok := w.(*observedWriter); ok {
		observed.fallback = len(result.Attempts) > 1
	}
	response := struct {
		parser.Result
		BodySHA256  string `json:"bodySHA256"`
		PaymentMode string `json:"paymentMode"`
		Error       string `json:"error,omitempty"`
	}{Result: result, BodySHA256: hash, PaymentMode: s.Config.Mode()}
	if err != nil {
		// A failed parse may contain partial text. Never release it without payment.
		response.Result = parser.Result{Attempts: result.Attempts}
		status := 502
		response.Error = "service_error"
		if errors.Is(err, parser.ErrDocument) {
			status = 422
			response.Error = "document_parse_failed"
		}
		if status == 422 && cacheableFailure(result) {
			// A completed document failure still consumes the abuse allowance
			// when its caller disconnects. This bounded, metadata-only operation
			// cannot settle a payment or turn cancellation into a parse failure.
			recordCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			recordDeadline, _ := recordCtx.Deadline()
			saved, saveErr := s.Pay(recordCtx, protocol.PaymentRequest{TraceID: telemetry.Trace(ctx), Header: h[0], BodySHA256: hash, BodyLength: int64(len(body)), Deadline: recordDeadline.Unix(), DocumentFailed: true})
			stop()
			if saveErr != nil || !saved.Pass || saved.Status != 0 || saved.Error != "" || saved.Settlement != nil || !validPaymentBackoff(saved) {
				slog.ErrorContext(ctx, "document failure cache write failed", "request_id", telemetry.Trace(ctx))
			}
		} else if r.Context().Err() != nil {
			s.recordAbandonment(ctx, h[0])
		}
		detail.Code = response.Error
		write(w, status, response)
		return
	}
	// Validate and buffer the complete response before committing any funds.
	prepareDone := detail.Step("prepare")
	encoded, encodeErr := json.Marshal(response)
	prepareDone()
	if encodeErr != nil || len(encoded) > protocol.MaxOutput {
		write(w, 502, map[string]string{"error": "response_encoding_failed"})
		return
	}
	if ctx.Err() != nil {
		if r.Context().Err() != nil {
			s.recordAbandonment(ctx, h[0])
		}
		write(w, 504, map[string]string{"error": "request_deadline"})
		return
	}
	if time.Until(deadline) < 20*time.Second {
		write(w, 503, map[string]string{"error": "insufficient_request_budget"})
		return
	}
	payCtx, payCancel := context.WithTimeout(ctx, 20*time.Second)
	paid, err := timedPay("settle", payCtx, protocol.PaymentRequest{TraceID: telemetry.Trace(ctx), Header: h[0], BodySHA256: hash, BodyLength: int64(len(body)), Deadline: deadline.Unix()})
	payExpired := payCtx.Err() != nil
	payCancel()
	if err != nil {
		write(w, 502, map[string]string{"error": "payment_unavailable"})
		return
	}
	if observed, ok := w.(*observedWriter); ok {
		observed.settled = s.Config.ForSize(int64(len(body))).ValidSettlement(paid.Settlement)
	}
	cfg := s.Config.ForSize(int64(len(body)))
	if !validPaymentBackoff(paid) || paid.Pass && (paid.Status != 0 || paid.Error != "" || !cfg.ValidSettlement(paid.Settlement)) {
		write(w, 502, map[string]string{"error": "invalid_payment_response"})
		return
	}
	if evidence := cfg.SettlementEvidence(paid.Settlement); evidence != nil {
		header, e := protocol.Header(evidence)
		if e != nil {
			write(w, 502, map[string]string{"error": "invalid_payment_response"})
			return
		}
		w.Header().Set("PAYMENT-RESPONSE", header)
	}
	if payExpired {
		write(w, 504, map[string]string{"error": "request_deadline"})
		return
	}
	if !paid.Pass {
		s.rejectPayment(w, paid, int64(len(body)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	detail.Stage = "write"
	w.WriteHeader(200)
	_, _ = w.Write(encoded)
}

func LambdaPay(client *awslambda.Client, alias string) PayFunc {
	return func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		var paid protocol.PaymentResponse
		// Cancelling Invoke stops the caller's wait, not the running Lambda.
		// Carry the shorter stage budget into the event so the function's own
		// provider/database contexts stop at the same deadline.
		if deadline, ok := ctx.Deadline(); ok && r.Deadline > deadline.Unix() {
			r.Deadline = deadline.Unix()
		}
		payload, err := json.Marshal(r)
		if err != nil || len(payload) > protocol.MaxPaymentPayload {
			return paid, errors.New("payment invocation too large")
		}
		out, err := client.Invoke(ctx, &awslambda.InvokeInput{FunctionName: aws.String(alias), InvocationType: lambdatypes.InvocationTypeRequestResponse, Payload: payload})
		if err != nil {
			return paid, err
		}
		if out.StatusCode != 200 || out.FunctionError != nil || len(out.Payload) > protocol.MaxPaymentPayload {
			return paid, errors.New("payment invocation failed")
		}
		err = jsonwire.Decode(out.Payload, &paid, protocol.MaxPaymentPayload)
		return paid, err
	}
}

// Invalid worker protocol/output can be an implementation failure. Never poison
// the document cache on that evidence, on setup failure, or on cancellation.
func cacheableFailure(result parser.Result) bool {
	if len(result.Attempts) == 0 {
		return false
	}
	for _, attempt := range result.Attempts {
		switch attempt.Outcome {
		case "document_error", "password_required", "timeout", "output_limit":
		default:
			return false
		}
	}
	return true
}
