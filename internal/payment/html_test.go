package payment

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	x402 "github.com/x402-foundation/x402/go/v2"
	exact "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"pdfservice/internal/htmltool"
	"pdfservice/internal/protocol"
)

const htmlResource = "https://api.example.com/v1/html/markdown"

func htmlSigned(t *testing.T) string {
	t.Helper()
	cfg := protocol.Config{}.ForHTML()
	s, err := signer.NewClientSignerFromPrivateKey(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := x402.Newx402Client().Register(x402.Network(cfg.Network()), exact.NewExactEvmScheme(s, nil)).CreatePaymentPayload(context.Background(), cfg.Requirements(), cfg.Quote(htmlResource).Resource, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload.Resource = cfg.Quote(htmlResource).Resource
	h, err := protocol.Header(payload)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func htmlCall(t *testing.T, c htmltool.Controller, header, url string, encoding ...string) (events.ALBTargetGroupResponse, string) {
	t.Helper()
	body, _ := json.Marshal(htmltool.Input{URL: url})
	event := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: htmltool.Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": header}, Body: string(body)}
	if len(encoding) > 0 {
		event.Headers["accept-encoding"] = encoding[0]
	}
	wire, _ := json.Marshal(event)
	encoded, err := c.Invoke(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	var out events.ALBTargetGroupResponse
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	decoded := []byte(out.Body)
	if out.IsBase64Encoded {
		decoded, err = base64.StdEncoding.DecodeString(out.Body)
		if err != nil {
			t.Fatal(err)
		}
	}
	if values := out.MultiValueHeaders["Content-Encoding"]; len(values) == 1 && values[0] == "gzip" {
		reader, e := gzip.NewReader(bytes.NewReader(decoded))
		if e != nil {
			t.Fatal(e)
		}
		decoded, err = io.ReadAll(io.LimitReader(reader, protocol.MaxHTMLResult+1))
		reader.Close()
		if err != nil || len(decoded) > protocol.MaxHTMLResult {
			t.Fatal("gzip result exceeded contract", err)
		}
	}
	return out, string(decoded)
}

func TestHTMLTransportFailureCanRetrySamePayment(t *testing.T) {
	store := &memoryStore{}
	facilitator := &countingFacilitator{}
	cfg := protocol.Config{}.ForHTML()
	service := Service{Store: store, Facilitator: facilitator, Resource: htmlResource, Config: cfg}
	text := strings.Repeat("complete source text\n", 110000)
	c := htmltool.Controller{Config: cfg, Resource: htmlResource,
		Pay: func(ctx context.Context, request protocol.PaymentRequest) (protocol.PaymentResponse, error) {
			return service.Handle(ctx, request), nil
		},
		Work: func(_ context.Context, input htmltool.Input) (htmltool.Result, error) {
			return htmltool.Result{URL: input.URL, FinalURL: input.URL, SourceStatus: 200, Markdown: text}, nil
		}}
	proof := htmlSigned(t)
	out, body := htmlCall(t, c, proof, "https://example.com/large")
	if out.StatusCode != 406 || !strings.Contains(body, "gzip_required") || facilitator.calls.Load() != 0 || len(store.rows) != 0 {
		t.Fatal("transport rejection settled or bound payment", out.StatusCode, facilitator.calls.Load(), len(store.rows))
	}
	out, body = htmlCall(t, c, proof, "https://example.com/large", "gzip")
	var result htmltool.Result
	if out.StatusCode != 200 || facilitator.calls.Load() != 1 || json.Unmarshal([]byte(body), &result) != nil || result.Markdown != text || result.Truncated {
		t.Fatal("same authorization could not deliver full result", out.StatusCode, facilitator.calls.Load())
	}
	firstReceipt := out.MultiValueHeaders["PAYMENT-RESPONSE"][0]
	out, _ = htmlCall(t, c, proof, "https://example.com/large", "gzip")
	if out.StatusCode != 200 || facilitator.calls.Load() != 1 || out.MultiValueHeaders["PAYMENT-RESPONSE"][0] != firstReceipt {
		t.Fatal("paid gzip retry charged again", out.StatusCode, facilitator.calls.Load())
	}
}
func TestHTMLControllerOfficialX402AndChangingContentRetry(t *testing.T) {
	store := &memoryStore{}
	facilitator := &countingFacilitator{}
	cfg := protocol.Config{}.ForHTML()
	service := Service{Store: store, Facilitator: facilitator, Resource: htmlResource, Config: cfg}
	calls := 0
	c := htmltool.Controller{Config: cfg, Resource: htmlResource, Pay: func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		return service.Handle(ctx, r), nil
	}, Work: func(_ context.Context, i htmltool.Input) (htmltool.Result, error) {
		calls++
		return htmltool.Result{URL: i.URL, FinalURL: i.URL, SourceStatus: 200, SourceBytes: 20, Markdown: strings.Repeat("changed ", calls)}, nil
	}}
	first := htmlSigned(t)
	out, body := htmlCall(t, c, first, "https://example.com/page")
	if out.StatusCode != 200 || out.MultiValueHeaders["PAYMENT-RESPONSE"] == nil || !strings.Contains(body, "changed") {
		t.Fatal(out, body)
	}
	out, body = htmlCall(t, c, first, "https://example.com/page")
	if out.StatusCode != 200 || !strings.Contains(body, "changed changed") {
		t.Fatal(out, body)
	}
	out, body = htmlCall(t, c, first, "https://example.com/other")
	if out.StatusCode != 409 || !strings.Contains(body, "payment_url_mismatch") || calls != 2 {
		t.Fatal("URL changed on same payment", out, calls)
	}
	for range 2 {
		out, _ = htmlCall(t, c, first, "https://example.com/page")
		if out.StatusCode != 200 {
			t.Fatal(out)
		}
	}
	out, _ = htmlCall(t, c, first, "https://example.com/page")
	if out.StatusCode != 429 || calls != 4 {
		t.Fatal("retry limit", out, calls)
	}
	out, _ = htmlCall(t, c, htmlSigned(t), "https://example.com/page")
	if out.StatusCode != 200 || calls != 5 || facilitator.calls.Load() != 2 {
		t.Fatal("new purchase blocked", out, calls, facilitator.calls.Load())
	}
}
func TestHTMLFailuresAreUnchargedAndNotCachedAsBadDocuments(t *testing.T) {
	store := &memoryStore{}
	facilitator := &countingFacilitator{}
	service := Service{Store: store, Facilitator: facilitator, Resource: htmlResource, Config: protocol.Config{}.ForHTML()}
	c := htmltool.Controller{Resource: htmlResource, Pay: func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		return service.Handle(ctx, r), nil
	}, Work: func(_ context.Context, i htmltool.Input) (htmltool.Result, error) {
		return htmltool.Result{Error: htmltool.ErrType.Error()}, nil
	}}
	for range 5 {
		out, _ := htmlCall(t, c, htmlSigned(t), "https://example.com/page")
		if out.StatusCode != 422 {
			t.Fatal(out)
		}
	}
	out, _ := htmlCall(t, c, htmlSigned(t), "https://example.com/page")
	if out.StatusCode != 429 || facilitator.calls.Load() != 0 || len(store.rows) != 0 || len(store.failures) != 0 {
		t.Fatal("failure quota or charge", out, facilitator.calls.Load(), store.rows, store.failures)
	}
}
func TestHTMLPaymentCannotBeSpentAgainByPDFTool(t *testing.T) {
	store := &memoryStore{}
	f := &countingFacilitator{}
	cfg := protocol.Config{}.ForHTML()
	h := htmlSigned(t)
	r := protocol.PaymentRequest{Tool: "html", Header: h, BodySHA256: protocol.SHA256([]byte("html-v1\x00https://example.com/")), BodyLength: 32, Deadline: time.Now().Unix() + 90}
	s := Service{Store: store, Facilitator: f, Resource: htmlResource, Config: cfg}
	if out := s.Handle(context.Background(), r); !out.Pass {
		t.Fatal(out)
	}
	raw, _ := base64.StdEncoding.DecodeString(h)
	var payload map[string]any
	json.Unmarshal(raw, &payload)
	payload["resource"] = protocol.Quote(testResource).Resource
	h, _ = protocol.Header(payload)
	pdf := Service{Store: store, Facilitator: f, Resource: testResource}
	out := pdf.Handle(context.Background(), request(h, "other PDF bytes"))
	if out.Pass || f.calls.Load() != 1 {
		t.Fatal("cross-tool payment replay", out, f.calls.Load())
	}
}
func TestHTMLMalformedAndMissingPaymentsNeverFetch(t *testing.T) {
	service := Service{Store: &memoryStore{}, Facilitator: &countingFacilitator{}, Resource: htmlResource, Config: protocol.Config{}.ForHTML()}
	work := 0
	c := htmltool.Controller{Resource: htmlResource, Pay: func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		return service.Handle(ctx, r), nil
	}, Work: func(context.Context, htmltool.Input) (htmltool.Result, error) { work++; return htmltool.Result{}, nil }}
	for _, h := range []string{"", "garbage", base64.StdEncoding.EncodeToString([]byte(`{"payload":{"authorization":{"from":"0x1111111111111111111111111111111111111111"}}}`))} {
		out, _ := htmlCall(t, c, h, "https://example.com/page")
		if out.StatusCode != http.StatusPaymentRequired {
			t.Fatal(out)
		}
	}
	if work != 0 {
		t.Fatal("unauthorized fetch", work)
	}
}

func TestHTMLJavaScriptResultSettlesThroughSameX402Flow(t *testing.T) {
	store := &memoryStore{}
	facilitator := &countingFacilitator{}
	cfg := protocol.Config{}.ForHTML().WithHTMLJavaScript(true)
	service := Service{Store: store, Facilitator: facilitator, Resource: htmlResource, Config: cfg}
	c := htmltool.Controller{Config: cfg, Resource: htmlResource, Pay: func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		return service.Handle(ctx, r), nil
	}, Work: func(_ context.Context, i htmltool.Input) (htmltool.Result, error) {
		return htmltool.Result{URL: i.URL, FinalURL: i.URL, SourceStatus: 200, SourceBytes: 20, JavaScript: true, Markdown: "rendered JavaScript"}, nil
	}}
	out, body := htmlCall(t, c, htmlSigned(t), "https://example.com/page")
	if out.StatusCode != 200 || out.MultiValueHeaders["PAYMENT-RESPONSE"] == nil || !strings.Contains(body, `"javascript":true`) {
		t.Fatal(out.StatusCode, body)
	}
}
