package payment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"pdfservice/internal/protocol"
)

func TestDocumentFailuresUseOnlyDirectKeyReadsAndSmallConditionalWrites(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	now := int64(1000)
	reads, writes := 0, 0
	expiry := now + 864000
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]any
		if json.NewDecoder(r.Body).Decode(&data) != nil {
			t.Error("bad request")
			http.Error(w, "bad request", 400)
			return
		}
		if data["TableName"] != "metadata" {
			t.Error("wrong table")
		}
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			reads++
			if data["ConsistentRead"] != true {
				t.Error("eventual document lookup")
			}
			key := data["Key"].(map[string]any)["paymentKey"].(map[string]any)["S"]
			if key != documentKey(hash) {
				t.Error("hash is not the primary key")
			}
			json.NewEncoder(w).Encode(map[string]any{"Item": map[string]any{"kind": map[string]string{"S": "document_failure"}, "expiresAt": map[string]string{"N": strconv.FormatInt(expiry, 10)}}})
		case "DynamoDB_20120810.PutItem":
			writes++
			if writes == 2 {
				w.Header().Set("Content-Type", "application/x-amz-json-1.0")
				w.WriteHeader(400)
				w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"entry already exists"}`))
				return
			}
			item := data["Item"].(map[string]any)
			if len(item) != 3 || item["kind"].(map[string]any)["S"] != "document_failure" || item["expiresAt"].(map[string]any)["N"] != strconv.FormatInt(now+864000, 10) || item["paymentKey"].(map[string]any)["S"] != documentKey(hash) || data["ConditionExpression"] != "attribute_not_exists(paymentKey) OR expiresAt <= :now" {
				t.Error("unexpected failure metadata or mutable TTL")
			}
			w.Write([]byte(`{}`))
		default:
			t.Error("scan, query, or another operation used")
		}
	}))
	defer ts.Close()
	cfg := aws.Config{Region: "us-east-2", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture"}, nil
	})}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ts.URL); o.RetryMaxAttempts = 1 })
	store := DynamoStore{Client: client, Table: "metadata"}
	if err := store.MarkFailed(context.Background(), hash, now); err != nil {
		t.Fatal(err)
	}
	if failed, err := store.Failed(context.Background(), hash, now); err != nil || !failed {
		t.Fatal(failed, err)
	}
	// Another failure cannot extend a fresh entry's TTL.
	if err := store.MarkFailed(context.Background(), hash, now+10); err != nil {
		t.Fatal("duplicate failure write", err)
	}
	for _, tc := range []struct {
		at   int64
		want bool
	}{{now + 86400, true}, {now + 864000 - 1, true}, {now + 864000, false}} {
		if failed, err := store.Failed(context.Background(), hash, tc.at); err != nil || failed != tc.want {
			t.Fatal("ten-day expiry boundary", tc.at, failed, err)
		}
	}
	if reads != 4 || writes != 2 {
		t.Fatal("unexpected operation count")
	}
}

func TestKnownFailureCheckAndRecordNeverSettleAndRejectForgedRecords(t *testing.T) {
	store := &memoryStore{}
	facilitator := &countingFacilitator{}
	s := Service{Store: store, Facilitator: facilitator, Resource: testResource}
	h := signed(t)
	r := request(h, "bad PDF")
	r.CheckDocument = true
	if out := s.Handle(context.Background(), r); !out.Pass || out.Settlement != nil {
		t.Fatal(out)
	}
	r.CheckDocument = false
	r.DocumentFailed = true
	r.Deadline = time.Now().Add(documentFailureDeadlineOffset).Unix()
	if out := s.Handle(context.Background(), r); !out.Pass || out.Settlement != nil {
		t.Fatal(out)
	}
	r.DocumentFailed = false
	r.CheckDocument = true
	if out := s.Handle(context.Background(), r); out.Status != 422 || out.Error != "document_known_unparseable" {
		t.Fatal(out)
	}
	if facilitator.calls.Load() != 0 || len(store.rows) != 0 {
		t.Fatal("document operations moved funds or wrote payment binding")
	}
	s.Now = func() time.Time { return time.Now().Add(DocumentFailureLifetime) }
	if failed, err := store.Failed(context.Background(), r.BodySHA256, s.now().Unix()); err != nil || failed {
		t.Fatal("failure did not expire")
	}
	// Mixed operations fail closed, before they can alter the table.
	r.VerifyOnly = true
	if out := s.Handle(context.Background(), r); out.Status != 400 {
		t.Fatal("mixed operations accepted", out)
	}
	bad := request(h, "another bad PDF")
	bad.DocumentFailed = true
	bad.Deadline = time.Now().Add(documentFailureDeadlineOffset).Unix()
	raw, _ := base64.StdEncoding.DecodeString(h)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["payload"].(map[string]any)["signature"] = "0x" + strings.Repeat("00", 65)
	bad.Header, _ = protocol.Header(payload)
	s.Now = nil
	if out := s.Handle(context.Background(), bad); out.Status != 402 {
		t.Fatal("forged failure record accepted", out)
	}
	if len(store.failures) != 1 || len(store.quotas) != 1 {
		t.Fatal("forged authorization poisoned cache")
	}
}

func TestInvalidResourceOutcomeOperationsFailBeforeStoreOrProvider(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	base := protocol.PaymentRequest{Deadline: now.Add(5 * time.Second).Unix()}
	for _, mutate := range []func(*protocol.PaymentRequest){
		func(r *protocol.PaymentRequest) { r.RecordOutcome = "unknown" },
		func(r *protocol.PaymentRequest) {
			r.RecordOutcome, r.VerifyOnly = protocol.PaymentOutcomeAbandoned, true
		},
		func(r *protocol.PaymentRequest) {
			r.RecordOutcome, r.BodySHA256, r.BodyLength = protocol.PaymentOutcomeAbandoned, strings.Repeat("0", 64), 1
		},
	} {
		r := base
		mutate(&r)
		service := Service{Now: func() time.Time { return now }}
		if out := service.Handle(context.Background(), r); out.Pass || out.Status != 400 {
			t.Fatalf("invalid outcome reached dependencies: request=%+v response=%+v", r, out)
		}
	}
}

func TestKnownFailedPDFRejectsIndependentPaymentsWithoutSettlement(t *testing.T) {
	store := &memoryStore{}
	f := &countingFacilitator{}
	s := Service{Store: store, Facilitator: f, Resource: testResource}
	first := request(signed(t), "identical bad PDF")
	first.DocumentFailed = true
	first.Deadline = time.Now().Add(documentFailureDeadlineOffset).Unix()
	if out := s.Handle(context.Background(), first); !out.Pass {
		t.Fatal(out)
	}
	for _, key := range []string{strings.Repeat("0", 63) + "1", strings.Repeat("0", 63) + "2"} {
		// Both a new authorization from the original payer and a different
		// payer share the PDF-only failure record, never a payment binding.
		r := request(signedWithKey(t, key), "identical bad PDF")
		if r.Header == first.Header {
			t.Fatal("fixture did not create an independent payment")
		}
		r.CheckDocument = true
		if out := s.Handle(context.Background(), r); out.Pass || out.Status != 422 || out.Error != "document_known_unparseable" || out.Settlement != nil {
			t.Fatal("independent payment bypassed PDF-only failure cache", out)
		}
		r.BodySHA256 = protocol.SHA256([]byte("different PDF"))
		if out := s.Handle(context.Background(), r); !out.Pass {
			t.Fatal("failure cache blocked different bytes", out)
		}
	}
	if f.calls.Load() != 0 || len(store.rows) != 0 || len(store.failures) != 1 {
		t.Fatal("known failures collected payment or stored requester metadata")
	}
}
