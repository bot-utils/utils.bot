package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"pdfservice/internal/protocol"
)

// This exercises the actual SDK wire payload. A cancelled Invoke HTTP request
// cannot cancel the independently running Lambda, so its serialized deadline
// must bound the work rather than relying on the SDK's caller context alone.
func TestLambdaInvocationCarriesStageDeadline(t *testing.T) {
	events := make(chan protocol.PaymentRequest, 1)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event protocol.PaymentRequest
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		events <- event
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pass":false,"status":402,"error":"invalid_payment"}`))
	}))
	defer endpoint.Close()
	client := awslambda.NewFromConfig(aws.Config{
		Region: "us-east-2", HTTPClient: endpoint.Client(),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}, func(o *awslambda.Options) { o.BaseEndpoint = aws.String(endpoint.URL) })
	pay := LambdaPay(client, "test-function:live")
	for _, test := range []struct {
		name   string
		budget time.Duration
		event  protocol.PaymentRequest
	}{
		{"verify", 10 * time.Second, protocol.PaymentRequest{VerifyOnly: true}},
		{"document-check", 5 * time.Second, protocol.PaymentRequest{CheckDocument: true}},
		{"failed-document", 5 * time.Second, protocol.PaymentRequest{DocumentFailed: true}},
		{"abandoned-request", 5 * time.Second, protocol.PaymentRequest{RecordOutcome: protocol.PaymentOutcomeAbandoned}},
		{"settlement", 20 * time.Second, protocol.PaymentRequest{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), test.budget)
			defer cancel()
			deadline, _ := ctx.Deadline()
			event := test.event
			event.Deadline = time.Now().Add(90 * time.Second).Unix()
			if response, err := pay(ctx, event); err != nil || response.Status != 402 {
				t.Fatalf("invocation failed: %v %+v", err, response)
			}
			if got := <-events; got.Deadline != deadline.Unix() {
				t.Fatalf("remote work outlives stage: deadline=%d stage=%d", got.Deadline, deadline.Unix())
			}
			// Never extend a shorter caller-supplied authorization/work deadline.
			event.Deadline = deadline.Add(-time.Second).Unix()
			if _, err := pay(ctx, event); err != nil {
				t.Fatal(err)
			}
			if got := <-events; got.Deadline != event.Deadline {
				t.Fatal("shorter event deadline was extended")
			}
		})
	}
}
