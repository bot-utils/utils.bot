package htmltool

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"pdfservice/internal/protocol"
)

func TestTextBoundaryRejectsHostileWorkerBeforeSettlement(t *testing.T) {
	base := Result{URL: "https://example.com/", FinalURL: "https://example.com/", SourceStatus: 200, JavaScript: true, Markdown: "hello"}
	for _, attack := range []string{"<script>alert(1)</script>", "\x1b[2J", "\x00binary", "\u202eevil", string([]byte{0xff}), strings.Repeat("a", MaxMarkdown+1)} {
		t.Run("malformed-text", func(t *testing.T) {
			result := base
			result.Markdown = attack
			settlements := 0
			c := Controller{Config: protocol.Config{}.WithHTMLJavaScript(true), Resource: "https://api.example.com" + Path, Pay: func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				if !r.VerifyOnly && !r.CheckDocument {
					settlements++
				}
				return protocol.PaymentResponse{Pass: true}, nil
			}, Work: func(context.Context, Input) (Result, error) { return result, nil }}
			e := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "x"}, Body: `{"url":"https://example.com/"}`}
			b, _ := json.Marshal(e)
			out, _ := c.Invoke(context.Background(), b)
			var response events.ALBTargetGroupResponse
			json.Unmarshal(out, &response)
			body := decodedALBBody(t, response)
			if settlements != 0 || response.StatusCode != 502 || !strings.Contains(string(body), "invalid_worker_response") {
				t.Fatal(response.StatusCode, settlements, string(body))
			}
		})
	}
	for _, change := range []func(*Result){func(r *Result) { r.Title = "<img onerror=evil>" }, func(r *Result) { r.Title = strings.Repeat("x", 1025) }, func(r *Result) { r.Error = "fetch_failed" }, func(r *Result) { r.FinalURL = "https://example.com/#hidden" }, func(r *Result) { r.URL = "https://other.example/" }} {
		r := base
		change(&r)
		if ValidateResult(r, Input{URL: base.URL}, true) {
			t.Fatal("invalid metadata accepted")
		}
	}
}
