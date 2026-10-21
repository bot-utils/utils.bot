package htmltool

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
	"pdfservice/internal/telemetry"
)

type PayFunc func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error)
type WorkFunc func(context.Context, Input) (Result, error)
type Controller struct {
	Config   protocol.Config
	Resource string
	Pay      PayFunc
	Work     WorkFunc
}

// Invoke has no content logging; the summary carries only fixed stage/status,
// timing and a server-generated trace. ALB access logs remain disabled.
func (c Controller) Invoke(ctx context.Context, payload []byte) (encoded []byte, invokeErr error) {
	started := time.Now()
	trace := telemetry.NewTrace()
	ctx = telemetry.WithTrace(ctx, trace)
	response := events.ALBTargetGroupResponse{StatusCode: 502, MultiValueHeaders: map[string][]string{
		"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"},
		"Access-Control-Allow-Origin": {"*"}, "Access-Control-Expose-Headers": {"PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Request-ID, Retry-After"}, "X-Request-ID": {trace}, "X-Payment-Mode": {c.Config.Mode()},
	}}
	stage := "headers"
	code := "conversion_unavailable"
	settled := false
	encoding := responseEncoding{identity: 1000}
	finish := func(status int, body any) {
		b, err := jsonwire.MarshalResponse(body)
		if err != nil || len(b) > MaxResult {
			status = 502
			b = []byte(`{"error":"conversion_unavailable"}`)
		}
		prepared, err := encodeALBResponse(response, status, b, encoding)
		if err != nil {
			// No supported representation is acceptable. An empty 406 does not
			// send an encoding the client explicitly refused.
			response.StatusCode, response.StatusDescription = 406, "406 Not Acceptable"
			response.Body, response.IsBase64Encoded = "", false
			delete(response.MultiValueHeaders, "Content-Encoding")
			response.MultiValueHeaders["Vary"] = []string{"Accept-Encoding"}
			return
		}
		response = prepared
	}
	fail := func(status int, reason string) { code = reason; finish(status, map[string]string{"error": reason}) }
	quote := func(reason string) {
		q := c.Config.ForHTML().Quote(c.Resource)
		q.Error = reason
		h, _ := protocol.Header(q)
		response.MultiValueHeaders["PAYMENT-REQUIRED"] = []string{h}
		code = reason
		finish(402, q)
	}
	defer func() {
		if recover() != nil {
			fail(502, "conversion_unavailable")
		}
		slog.InfoContext(ctx, "HTML request summary", "role", "html", "request_id", trace, "status", response.StatusCode, "stage", stage, "code", code, "settled", settled, "elapsed_ms", telemetry.Milliseconds(started))
		encoded, _ = json.Marshal(response)
		invokeErr = nil
	}()
	var event events.ALBTargetGroupRequest
	if jsonwire.Unmarshal(payload, &event, 64<<10) != nil {
		fail(400, "invalid_request")
		return
	}
	if event.Path != Path {
		fail(404, "not_found")
		return
	}
	if len(event.QueryStringParameters) > 0 || len(event.MultiValueQueryStringParameters) > 0 {
		fail(400, "noncanonical_request_url")
		return
	}
	if event.HTTPMethod == http.MethodOptions {
		response.MultiValueHeaders["Access-Control-Allow-Methods"] = []string{"POST, OPTIONS"}
		response.MultiValueHeaders["Access-Control-Allow-Headers"] = []string{"Content-Type, PAYMENT-SIGNATURE"}
		finish(204, nil)
		response.Body = ""
		response.IsBase64Encoded = false
		return
	}
	if event.HTTPMethod != http.MethodPost {
		response.MultiValueHeaders["Allow"] = []string{"POST, OPTIONS"}
		fail(405, "method_not_allowed")
		return
	}
	headers, ok := singleHeaders(event)
	if !ok {
		fail(400, "invalid_headers")
		return
	}
	configured, err := url.Parse(c.Resource)
	if err != nil || configured.Host == "" || configured.Path != Path {
		fail(502, "configuration_unavailable")
		return
	}
	if host := headers["host"]; !strings.EqualFold(host, configured.Host) && !strings.EqualFold(host, configured.Host+":443") {
		fail(400, "invalid_host")
		return
	}
	encoding, err = parseResponseEncoding(headers["accept-encoding"])
	if err != nil {
		encoding = responseEncoding{identity: 1000}
		fail(400, "invalid_accept_encoding")
		return
	}
	if encoding.identity == 0 && encoding.gzip == 0 {
		fail(406, "encoding_not_acceptable")
		return
	}
	header := headers["payment-signature"]
	if header == "" {
		quote("payment_required")
		return
	}
	if len(header) > protocol.MaxPaymentHeader {
		quote("invalid_payment")
		return
	}
	typ, params, err := mime.ParseMediaType(headers["content-type"])
	if err != nil || typ != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) || headers["content-encoding"] != "" && headers["content-encoding"] != "identity" {
		fail(415, "json_required")
		return
	}
	if len(event.Body) > base64.StdEncoding.EncodedLen(MaxRequest) {
		fail(413, "request_size_limit")
		return
	}
	body := []byte(event.Body)
	if event.IsBase64Encoded {
		body, err = base64.StdEncoding.Strict().DecodeString(event.Body)
		if err != nil {
			fail(400, "invalid_request")
			return
		}
	}
	if length := headers["content-length"]; length != "" {
		n, e := strconv.ParseInt(length, 10, 64)
		if e != nil || n != int64(len(body)) {
			fail(400, "invalid_request")
			return
		}
	}
	var input Input
	if jsonwire.Decode(body, &input, MaxRequest) != nil {
		fail(400, "invalid_request")
		return
	}
	canonical, err := CanonicalURL(input.URL)
	if err != nil {
		fail(400, Code(err))
		return
	}
	input.URL = canonical.String()
	// URL + operation binding is deliberately independent of fetched HTML. A paid
	// retry may see new source content, but cannot buy another URL or another tool.
	binding := []byte("html-v1\x00" + input.URL)
	deadline := time.Now().Add(protocol.HTMLRequestSeconds * time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	request := protocol.PaymentRequest{Tool: "html", TraceID: trace, Header: header, Deadline: deadline.Unix()}
	paymentError := func(out protocol.PaymentResponse, err error) bool {
		if err != nil {
			fail(502, "payment_unavailable")
			return true
		}
		if out.Pass {
			return false
		}
		status := out.Status
		if status < 400 || status > 599 {
			status = 502
		}
		if status == 402 {
			quote("invalid_payment")
			return true
		}
		if out.RetryAfter > 0 {
			response.MultiValueHeaders["Retry-After"] = []string{strconv.FormatInt(out.RetryAfter, 10)}
		}
		if evidence := c.Config.ForHTML().SettlementEvidence(out.Settlement); evidence != nil {
			h, _ := protocol.Header(evidence)
			response.MultiValueHeaders["PAYMENT-RESPONSE"] = []string{h}
		}
		// Provider messages never pass through this boundary.
		allowed := map[string]bool{"payment_in_progress": true, "retry_limit_reached": true, "retry_window_expired": true, "payment_document_mismatch": true, "request_abandonment_quota_exceeded": true, "unpaid_compute_quota_exceeded": true}
		reason := "payment_unavailable"
		if allowed[out.Error] {
			reason = out.Error
		}
		if reason == "payment_document_mismatch" {
			reason = "payment_url_mismatch"
		}
		fail(status, reason)
		return true
	}
	stage = "verify"
	request.VerifyOnly = true
	approval, err := c.Pay(ctx, request)
	if paymentError(approval, err) {
		return
	}
	request.VerifyOnly = false
	request.CheckDocument = true
	request.BodySHA256 = protocol.SHA256(binding)
	request.BodyLength = int64(len(binding))
	approval, err = c.Pay(ctx, request)
	if paymentError(approval, err) {
		return
	}
	request.CheckDocument = false
	stage = "fetch_convert"
	result, err := c.Work(ctx, input)
	if err != nil {
		fail(502, "conversion_unavailable")
		return
	}
	if !ValidateResult(result, input, c.Config.HTMLJavaScript()) {
		fail(502, "invalid_worker_response")
		return
	}
	if result.Error != "" {
		switch result.Error {
		case ErrBlocked.Error(), ErrURL.Error(), ErrFetch.Error(), ErrType.Error(), ErrSize.Error(), ErrComplexity.Error():
			callback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			r := request
			r.DocumentFailed = true
			r.Deadline = time.Now().Unix() + 5
			out, e := c.Pay(callback, r)
			cancel()
			if e != nil || !out.Pass {
				fail(502, "payment_store_unavailable")
				return
			}
			if result.Error == ErrBlocked.Error() {
				fail(403, result.Error)
			} else {
				fail(422, result.Error)
			}
		default:
			fail(503, "conversion_unavailable")
		}
		return
	}
	// All checks/serialization that can reject the result run BEFORE settlement.
	b, err := jsonwire.MarshalResponse(result)
	if err != nil || len(b) > MaxResult || len(result.Markdown) > MaxMarkdown || result.JavaScript != c.Config.HTMLJavaScript() || result.URL != input.URL || result.SourceStatus < 100 || result.SourceStatus > 599 || result.SourceBytes < 0 || result.SourceBytes > MaxHTML {
		fail(502, "invalid_worker_response")
		return
	}
	if _, err := CanonicalURL(result.FinalURL); err != nil {
		fail(502, "invalid_worker_response")
		return
	}
	paidResponse := response
	paidResponse.MultiValueHeaders = maps.Clone(response.MultiValueHeaders)
	paidResponse.MultiValueHeaders["PAYMENT-RESPONSE"] = []string{maximumSettlementReceipt(c.Config.ForHTML())}
	prepared, err := encodeALBResponse(paidResponse, 200, b, encoding)
	if err != nil {
		if errors.Is(err, errGzipRequired) {
			fail(406, "gzip_required")
		} else {
			fail(422, "response_size_limit")
		}
		return
	}
	stage = "settle"
	request.Deadline = time.Now().Unix() + 20
	approval, err = c.Pay(ctx, request)
	if paymentError(approval, err) {
		return
	}
	if !c.Config.ForHTML().ValidSettlement(approval.Settlement) {
		fail(502, "payment_unavailable")
		return
	}
	settled = true
	receipt, _ := protocol.Header(c.Config.ForHTML().SettlementEvidence(approval.Settlement))
	response = prepared
	response.MultiValueHeaders["PAYMENT-RESPONSE"] = []string{receipt}
	stage = "response"
	code = ""
	return
}

func singleHeaders(event events.ALBTargetGroupRequest) (map[string]string, bool) {
	out := make(map[string]string)
	if len(event.Headers) > 0 && len(event.MultiValueHeaders) > 0 {
		return nil, false
	}
	total := 0
	add := func(k, v string) bool {
		k = strings.ToLower(k)
		total += len(k) + len(v)
		if _, exists := out[k]; exists || strings.ContainsAny(v, "\r\n\x00") || total > 32<<10 {
			return false
		}
		out[k] = v
		return true
	}
	for k, v := range event.Headers {
		if !add(k, v) {
			return nil, false
		}
	}
	for k, values := range event.MultiValueHeaders {
		if len(values) != 1 || !add(k, values[0]) {
			return nil, false
		}
	}
	return out, true
}
