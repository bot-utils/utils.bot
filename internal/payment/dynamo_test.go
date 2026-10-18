package payment

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDynamoStrongReadAndImmutableMetadataWrite(t *testing.T) {
	reads, writes := 0, 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid AWS request")
		}
		if body["TableName"] != "test-bindings" {
			t.Error("unexpected table")
		}
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			reads++
			if body["ConsistentRead"] != true {
				t.Error("eventual binding read")
			}
			_, _ = w.Write([]byte(`{}`))
		case "DynamoDB_20120810.PutItem":
			writes++
			if body["ConditionExpression"] != "attribute_not_exists(paymentKey)" {
				t.Error("mutable binding")
			}
			item := body["Item"].(map[string]any)
			if len(item) != 7 {
				t.Errorf("unexpected metadata fields: %d", len(item))
			}
			for _, key := range []string{"paymentKey", "bodySHA256", "bodyLength", "paymentProofSHA256", "transaction", "retryUntil", "expiresAt"} {
				if _, ok := item[key]; !ok {
					t.Error("missing metadata", key)
				}
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Error("unexpected AWS operation")
		}
	}))
	defer testServer.Close()
	cfg := aws.Config{Region: "us-east-2", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "test-only"}, nil
	})}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(testServer.URL); o.RetryMaxAttempts = 1 })
	store := DynamoStore{Client: client, Table: "test-bindings"}
	if b, err := store.Get(context.Background(), "key"); err != nil || b != nil {
		t.Fatal("empty binding", err)
	}
	b := Binding{PaymentKey: "key", BodySHA256: strings.Repeat("ab", 32), BodyLength: 1, PaymentProofSHA256: strings.Repeat("cd", 32), Transaction: "0x" + strings.Repeat("ef", 32), RetryUntil: 100, ExpiresAt: 200}
	if err := store.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || writes != 1 {
		t.Fatal("unexpected operation count")
	}
}
