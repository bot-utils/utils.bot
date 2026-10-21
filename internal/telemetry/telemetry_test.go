package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTraceRejectsUntrustedContent(t *testing.T) {
	ctx := WithTrace(context.Background(), NewTrace())
	if len(Trace(ctx)) != 32 {
		t.Fatal("missing random correlation")
	}
	for _, input := range []string{"wallet-secret", strings.Repeat("z", 32), strings.Repeat("a", 33), "\n" + strings.Repeat("a", 31)} {
		if Trace(WithTrace(context.Background(), input)) != "" {
			t.Fatal("untrusted trace accepted")
		}
	}
}

func TestHTTPTransportDiagnosticsNeverRetainRequesterData(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(previous)
	// Other tests may have consumed the shared minute's diagnostic allowance;
	// advancing its previous window keeps this test independent of order.
	details.mu.Lock()
	details.start = time.Now().Add(-2 * time.Minute)
	details.mu.Unlock()
	p := []byte("http: panic serving 198.51.100.42:12345: private PDF and payment data\nstack")
	for range 10 {
		if n, err := (HTTPErrorWriter{}).Write(p); n != len(p) || err != nil {
			t.Fatal("transport log write failed", n, err)
		}
	}
	if strings.Contains(buf.String(), "198.51.100.42") || strings.Contains(buf.String(), "private PDF") || strings.Contains(buf.String(), "stack") || !strings.Contains(buf.String(), "http_transport_failure") || strings.Count(buf.String(), "\n") != 5 {
		t.Fatal("raw HTTP diagnostics or uncapped volume retained", buf.String())
	}
}
func TestLimiterCapsConcurrentDiagnosticVolume(t *testing.T) {
	var limiter Limiter
	now := time.Now()
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Allow(now) {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 5 || limiter.Allow(now.Add(59*time.Second)) || !limiter.Allow(now.Add(time.Minute)) {
		t.Fatal("diagnostic cap failed")
	}
}
func TestSummaryPrivacyBoundsAndOutcomeClassification(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(previous)
	ctx := WithTrace(context.Background(), NewTrace())
	PaymentSummary(ctx, Payment{ProviderFailures: 1, Code: strings.Repeat("provider-secret", 10000)}, time.Now())
	cases := []struct {
		status                                       int
		write, settled, fallback                     bool
		completed, document, service, paid, capacity int
	}{
		{200, false, true, false, 1, 0, 0, 0, 0}, {422, false, true, true, 0, 1, 0, 0, 0}, {502, false, true, false, 0, 0, 1, 1, 0}, {200, true, true, false, 0, 0, 1, 1, 0}, {429, false, false, false, 0, 0, 0, 0, 1},
	}
	for _, tc := range cases {
		RequestSummary(ctx, tc.status, tc.write, tc.settled, tc.fallback, time.Now())
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(cases)+1 {
		t.Fatal("missing terminal summaries")
	}
	for i, line := range lines {
		if len(line) > 1024 || strings.Contains(line, "provider-secret") {
			t.Fatal("unbounded diagnostic or customer text")
		}
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			t.Fatal("not JSON")
		}
		if i == 0 {
			if record["code"] != "unknown" || record["provider_failures"] != float64(1) {
				t.Fatal(record)
			}
			continue
		}
		tc := cases[i-1]
		for key, want := range map[string]int{"completed": tc.completed, "document_failures": tc.document, "service_failures": tc.service, "paid_service_failures": tc.paid, "capacity_refusals": tc.capacity, "fallback_attempts": Count(tc.fallback)} {
			if record[key] != float64(want) {
				t.Fatalf("%s=%v want %d", key, record[key], want)
			}
		}
	}
	if Code("unpaid_compute_quota_exceeded") != "unpaid_compute_quota_exceeded" || Code("request_abandonment_quota_exceeded") != "request_abandonment_quota_exceeded" || Reason("signature containing arbitrary data") != "unknown" || Reason("billing_required") != "billing_required" {
		t.Fatal("provider reason whitelist bypassed")
	}
}

func TestLeanSummaryHasOnlyApprovedFieldsAndSanitizesCategories(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(previous)
	r := Request{Route: "/private-customer-canary", Method: "PRIVATE-method", Stage: "PRIVATE request value", Code: "PRIVATE signature", PDFium: "PRIVATE PDF text", Poppler: "PRIVATE wallet"}
	RequestDetailSummary(WithTrace(context.Background(), NewTrace()), 502, false, false, false, time.Now(), r)
	var record map[string]any
	if json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record) != nil {
		t.Fatal(buf.String())
	}
	allowed := map[string]bool{}
	for _, key := range strings.Fields("time level msg telemetry role schema route method request_id status outcome code stage panic_recovered elapsed_ms verify_ms upload_ms check_ms parse_ms prepare_ms settle_ms pdfium poppler requests tool_requests quotes_issued payment_rejections completed document_failures service_failures paid_service_failures capacity_refusals fallback_attempts write_failed") {
		allowed[key] = true
	}
	for key := range record {
		if !allowed[key] {
			t.Fatal("new log field requires privacy review", key)
		}
	}
	if record["route"] != "unsupported" || record["method"] != "OTHER" {
		t.Fatal("unsafe access fields", record)
	}
	if strings.Contains(buf.String(), "PRIVATE") || strings.Contains(buf.String(), "private-customer-canary") || buf.Len() > 1536 {
		t.Fatal("unbounded/customer data", buf.String())
	}
	for _, key := range []string{"stage", "code", "pdfium", "poppler"} {
		if record[key] != "unknown" {
			t.Fatal(key, record)
		}
	}
}

func TestAccessFieldsAreFiniteAndNeverIncludeCustomerData(t *testing.T) {
	for _, path := range []string{"/v1/pdf/text", "/health", "/docs", "/openapi"} {
		if AccessRoute(path) != path {
			t.Fatal(path)
		}
	}
	for _, path := range []string{"/private/customer@example.com", "/v1/pdf/text?token=secret", "https://customer.example/secret", "/health\nsecret", "/v1/pdf/text/private", "//docs"} {
		if AccessRoute(path) != "unsupported" {
			t.Fatal("raw route retained", path)
		}
	}
	if AccessMethod("CUSTOMER_SECRET") != "OTHER" || AccessMethod("POST") != "POST" {
		t.Fatal("unsafe method")
	}
}

func TestRejectionFlagsAreLimitedToTheCanonicalURLError(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	for _, tc := range []struct {
		status int
		code   string
		want   bool
	}{
		{400, "noncanonical_request_url", true}, {200, "noncanonical_request_url", false}, {400, "invalid_payment", false},
	} {
		logs.Reset()
		RequestDetailSummary(context.Background(), tc.status, false, false, false, time.Now(), Request{Code: tc.code, NoncanonicalQuery: true, NoncanonicalPath: true})
		var record map[string]any
		if json.Unmarshal(logs.Bytes(), &record) != nil {
			t.Fatal("invalid log JSON")
		}
		_, present := record["query_present"]
		if present != tc.want || (present && (record["query_present"] != true || record["encoded_path"] != true)) || record["rejected_url"] != nil {
			t.Fatal("unexpected URL telemetry", record)
		}
	}
}

func TestOnlyPostedToolsCountAsCompletions(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	for _, tc := range []struct {
		route, method string
		want          float64
	}{
		{"/health", "GET", 0}, {"/docs", "GET", 0}, {"/v1/pdf/text", "GET", 0}, {"/v1/pdf/text", "HEAD", 0}, {"/v1/pdf/text", "POST", 1}, {"/v1/html/markdown", "POST", 1}, {"/v1/html/markdown", "GET", 0},
	} {
		logs.Reset()
		RequestDetailSummary(context.Background(), 200, false, false, false, time.Now(), Request{Route: tc.route, Method: tc.method})
		var record map[string]any
		if json.Unmarshal(logs.Bytes(), &record) != nil || record["completed"] != tc.want || record["tool_requests"] != tc.want {
			t.Fatal("incorrect tool count", tc, record)
		}
	}
}

func TestOutcomeLabelsDistinguishQuotesPaymentRejectionsAndFailures(t *testing.T) {
	for _, route := range []string{"/v1/pdf/text", "/v1/html/markdown"} {
		for _, tc := range []struct {
			status            int
			stage, code, want string
			quote, rejected   float64
		}{
			{402, "headers", "", "quote_issued", 1, 0},
			{402, "headers", "invalid_payment", "request_rejected", 0, 0},
			{400, "headers", "invalid_payment_header", "payment_rejected", 0, 1},
			{402, "verify", "invalid_payment", "payment_rejected", 0, 1},
			{402, "document_check", "payment_amount_mismatch", "payment_rejected", 0, 1},
			{402, "document_check", "invalid_payment", "payment_rejected", 0, 1},
			{402, "settle", "invalid_payment", "payment_rejected", 0, 1},
			{402, "settle", "payment_unavailable", "request_rejected", 0, 0},
			{502, "verify", "payment_unavailable", "service_failure", 0, 0},
			{502, "settle", "payment_unavailable", "service_failure", 0, 0},
			{503, "settle", "payment_confirmation_unavailable", "service_failure", 0, 0},
			{422, "document_check", "document_known_unparseable", "document_failure", 0, 0},
			{200, "write", "", "completed", 0, 0},
			{422, "parse", "document_parse_failed", "document_failure", 0, 0},
			{429, "headers", "capacity_exceeded", "capacity_refusal", 0, 0},
		} {
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			RequestDetailSummary(context.Background(), tc.status, false, false, false, time.Now(), Request{Route: route, Method: "POST", Stage: tc.stage, Code: tc.code})
			slog.SetDefault(old)
			var v map[string]any
			if json.Unmarshal(logs.Bytes(), &v) != nil || v["outcome"] != tc.want || v["quotes_issued"] != tc.quote || v["payment_rejections"] != tc.rejected || v["stage"] != tc.stage || v["code"] != Code(tc.code) {
				t.Fatal("incorrect outcome", route, tc, v)
			}
		}
	}
}
