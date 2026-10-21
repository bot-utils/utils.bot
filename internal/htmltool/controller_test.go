package htmltool

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"pdfservice/internal/htmllimits"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	x402 "github.com/x402-foundation/x402/go/v2"
	"pdfservice/internal/protocol"
)

func TestControllerRejectsAmbiguousInputAndNeverLeaksCustomerData(t *testing.T) {
	var logs bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(prior)
	invoked := 0
	c := Controller{Resource: "https://api.example.com" + Path, Pay: func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		invoked++
		return protocol.PaymentResponse{}, errors.New("private-provider-canary")
	}}
	base := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "customer-proof-canary"}, Body: `{"url":"https://example.com/private-customer-canary"}`}
	cases := []events.ALBTargetGroupRequest{}
	q := base
	q.HTTPMethod = "PUT"
	cases = append(cases, q)
	q = base
	q.Path = "/unknown"
	cases = append(cases, q)
	q = base
	q.Body = `{"url":"https://example.com","URL":"https://other.example"}`
	cases = append(cases, q)
	q = base
	q.Body = `{"url":"https://example.com","extra":true}`
	cases = append(cases, q)
	q = base
	q.MultiValueHeaders = map[string][]string{"Payment-Signature": {"first", "second"}}
	cases = append(cases, q)
	q = base
	q.QueryStringParameters = map[string]string{"x": "1"}
	cases = append(cases, q)
	q = base
	q.Body = strings.Repeat("x", MaxRequest+1)
	cases = append(cases, q)
	for _, event := range cases {
		b, _ := json.Marshal(event)
		wire, err := c.Invoke(context.Background(), b)
		var out events.ALBTargetGroupResponse
		json.Unmarshal(wire, &out)
		if err != nil || out.StatusCode < 400 || out.StatusCode == 502 {
			t.Fatal(out, err)
		}
	}
	if invoked != 0 {
		t.Fatal("malformed request invoked payment", invoked)
	}
	b, _ := json.Marshal(base)
	out, _ := c.Invoke(context.Background(), b)
	if bytes.Contains(out, []byte("private-provider-canary")) {
		t.Fatal("provider error leaked")
	}
	for _, s := range []string{"customer-proof-canary", "private-customer-canary", "private-provider-canary", "example.com"} {
		if strings.Contains(logs.String(), s) {
			t.Fatal("customer data logged", s)
		}
	}
}
func TestALBEnvelopeRemainsBelowOneMiB(t *testing.T) {
	// Worst JSON escaping inside result and the ALB envelope is accounted for.
	result := Result{URL: "https://example.com/", FinalURL: "https://example.com/", SourceStatus: 200, Markdown: strings.Repeat("\x00", MaxMarkdown)}
	encoded, _ := json.Marshal(result)
	if len(encoded) <= MaxResult {
		t.Fatal("test does not exceed result budget")
	}
	c := Controller{Resource: "https://api.example.com" + Path, Pay: func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		return protocol.PaymentResponse{Pass: true}, nil
	}, Work: func(context.Context, Input) (Result, error) { return result, nil }}
	event := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "x"}, Body: `{"url":"https://example.com/"}`}
	b, _ := json.Marshal(event)
	wire, _ := c.Invoke(context.Background(), b)
	var out events.ALBTargetGroupResponse
	json.Unmarshal(wire, &out)
	if out.StatusCode != 502 || len(wire) >= 1<<20 {
		t.Fatal(out.StatusCode, len(wire))
	}
}

type lambdaStub struct{ requests []*lambda.InvokeInput }

func (s *lambdaStub) Invoke(_ context.Context, in *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	s.requests = append(s.requests, in)
	return &lambda.InvokeOutput{StatusCode: 200, Payload: []byte(`{"url":"https://example.com/","finalURL":"https://example.com/","sourceStatus":200,"title":"","markdown":"hello","truncated":false,"javascript":false,"sourceBytes":10}`)}, nil
}
func TestEveryWorkerJobGetsANewUnpredictableTenant(t *testing.T) {
	client := &lambdaStub{}
	work := WorkerInvoker(client, "qualified-worker-arn")
	for range 3 {
		if _, err := work(context.Background(), Input{URL: "https://example.com/"}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, r := range client.requests {
		if r.TenantId == nil || len(*r.TenantId) != 64 || seen[*r.TenantId] {
			t.Fatal("missing/reused isolation ID")
		}
		seen[*r.TenantId] = true
		if bytes.Contains(r.Payload, []byte("header")) {
			t.Fatal("payment forwarded to worker")
		}
	}
}
func TestControllerContainsPanic(t *testing.T) {
	c := Controller{Resource: "https://api.example.com" + Path, Pay: func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		panic("private-panic-canary")
	}}
	e := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "x"}, Body: `{"url":"https://example.com/"}`}
	b, _ := json.Marshal(e)
	wire, err := c.Invoke(context.Background(), b)
	var out events.ALBTargetGroupResponse
	json.Unmarshal(wire, &out)
	body := decodedALBBody(t, out)
	if err != nil || out.StatusCode != 502 || bytes.Contains(body, []byte("canary")) {
		t.Fatal(out, err)
	}
}

func TestInfrastructureFailuresDoNotConsumeWalletAllowance(t *testing.T) {
	calls := 0
	c := Controller{Resource: "https://api.example.com" + Path, Pay: func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		calls++
		if r.RecordOutcome != "" || r.DocumentFailed {
			t.Error("service failure attributed to wallet")
		}
		return protocol.PaymentResponse{Pass: true}, nil
	}, Work: func(context.Context, Input) (Result, error) { return Result{Error: ErrThreats.Error()}, nil }}
	event := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "x"}, Body: `{"url":"https://example.com/"}`}
	b, _ := json.Marshal(event)
	wire, _ := c.Invoke(context.Background(), b)
	var out events.ALBTargetGroupResponse
	json.Unmarshal(wire, &out)
	if out.StatusCode != 503 || calls != 2 {
		t.Fatal(out.StatusCode, calls)
	}
}
func TestWorkerStripsBinaryControlsBeforeResponse(t *testing.T) {
	w := Worker{Load: func(context.Context) (DomainCheck, error) { return snapshot(t, "evil.example"), nil }, Fetch: func(_ context.Context, raw string, _ DomainCheck) (Result, error) {
		return Result{URL: raw, FinalURL: raw, SourceStatus: 200, Markdown: strings.Repeat("\x00", MaxMarkdown)}, nil
	}}
	wire, _ := w.Invoke(context.Background(), []byte(`{"url":"https://example.com/"}`))
	var result Result
	json.Unmarshal(wire, &result)
	if len(wire) > MaxResult || result.Markdown != "" || result.Error != "" {
		t.Fatal("escaped-output budget", len(wire), result.Error, result.Truncated)
	}
}

func TestControllerRejectsWrongRendererBeforeSettlement(t *testing.T) {
	for _, expected := range []bool{false, true} {
		settled := false
		c := Controller{Config: protocol.Config{}.WithHTMLJavaScript(expected), Resource: "https://api.example.com" + Path,
			Pay: func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				if !r.VerifyOnly && !r.CheckDocument {
					settled = true
				}
				return protocol.PaymentResponse{Pass: true}, nil
			},
			Work: func(context.Context, Input) (Result, error) {
				return Result{URL: "https://example.com/", FinalURL: "https://example.com/", SourceStatus: 200, JavaScript: !expected}, nil
			}}
		event := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "x"}, Body: `{"url":"https://example.com/"}`}
		b, _ := json.Marshal(event)
		wire, _ := c.Invoke(context.Background(), b)
		var out events.ALBTargetGroupResponse
		json.Unmarshal(wire, &out)
		if out.StatusCode != 502 || settled {
			t.Fatal("mismatched renderer settled", expected, out.StatusCode, settled)
		}
	}
}

func TestControllerAttributesRenderBudgetAndNeverSettlesFailedJobs(t *testing.T) {
	for _, reason := range []error{ErrBlocked, ErrURL, ErrFetch, ErrType, ErrSize, ErrComplexity, ErrThreats} {
		t.Run(reason.Error(), func(t *testing.T) {
			failed, settled := 0, 0
			c := Controller{Config: protocol.Config{}.ForHTML().WithHTMLJavaScript(true), Resource: "https://api.example.com" + Path,
				Pay: func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
					if r.DocumentFailed {
						failed++
					} else if !r.VerifyOnly && !r.CheckDocument {
						settled++
					}
					return protocol.PaymentResponse{Pass: true}, nil
				}, Work: func(context.Context, Input) (Result, error) { return Result{Error: reason.Error()}, nil }}
			event := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "x"}, Body: `{"url":"https://example.com/"}`}
			wire, _ := json.Marshal(event)
			wire, _ = c.Invoke(context.Background(), wire)
			var out events.ALBTargetGroupResponse
			json.Unmarshal(wire, &out)
			expectedFailures := 1
			if reason == ErrThreats {
				expectedFailures = 0
			}
			if failed != expectedFailures || settled != 0 || out.StatusCode < 400 {
				t.Fatal(out.StatusCode, failed, settled)
			}
		})
	}
}

func TestMaximumCompressedBodyFitsCompleteALBResponse(t *testing.T) {
	// Use the exact production header names, the longest mode, trace and maximum
	// settlement evidence, then measure the actual Lambda envelope serialization.
	cfg, _ := protocol.NewConfig(protocol.ModeBase, "0x"+strings.Repeat("2", 40))
	settlement := &x402.SettleResponse{Success: true, Payer: "0x" + strings.Repeat("a", 40), Transaction: "0x" + strings.Repeat("b", 64), Network: x402.Network(cfg.Network())}
	receipt, _ := protocol.Header(cfg.SettlementEvidence(settlement))
	response := events.ALBTargetGroupResponse{StatusCode: 200, StatusDescription: "200 OK", IsBase64Encoded: true, Body: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), htmllimits.MaxCompressedBody)), MultiValueHeaders: map[string][]string{
		"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}, "Vary": {"Accept-Encoding"}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"}, "Access-Control-Allow-Origin": {"*"}, "Access-Control-Expose-Headers": {"PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Request-ID, Retry-After"}, "X-Request-ID": {strings.Repeat("a", 64)}, "X-Payment-Mode": {cfg.Mode()}, "PAYMENT-RESPONSE": {receipt},
	}}
	wire, err := json.Marshal(response)
	if err != nil || len(wire) > htmllimits.ALBMaxResponse {
		t.Fatal("ALB overflow", len(wire), err)
	}
	overhead := len(wire) - len(response.Body)
	if overhead > htmllimits.ALBEnvelopeReserve {
		t.Fatal("header reservation exceeded", overhead)
	}
	t.Logf("compressed_body=%d base64=%d envelope=%d total=%d spare=%d", htmllimits.MaxCompressedBody, len(response.Body), overhead, len(wire), htmllimits.ALBMaxResponse-len(wire))
}
