package payment

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"pdfservice/internal/protocol"
)

// Run against the CDK-created LocalStack table through the payment-role policy
// stub. This checks DynamoDB conditions, not a mocked in-memory counter.
func TestDynamoAtomicReservationAndRetryLimit(t *testing.T) {
	endpoint := os.Getenv("PDF_TEST_DYNAMO_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the LocalStack workflow")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "localhost" {
		t.Fatal("test endpoint must be loopback LocalStack")
	}
	cfg := aws.Config{Region: "us-east-2", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
	})}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint); o.RetryMaxAttempts = 1 })
	s := DynamoStore{Client: client, Table: "agent-pdf-mock-payments"}
	ctx := context.Background()
	now := time.Now().Unix()
	b := Binding{PaymentKey: fmt.Sprintf("test:retry:%d", time.Now().UnixNano()), State: preparedState,
		ReservationID: strings.Repeat("12", 16), BodySHA256: strings.Repeat("ab", 32), BodyLength: 10,
		PaymentProofSHA256: strings.Repeat("cd", 32), RetryUntil: now + 300, ExpiresAt: now + 600}
	if err := s.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, b); err != ErrConflict {
		t.Fatalf("reservation overwritten: %v", err)
	}
	if err := s.ClaimRetry(ctx, b, now); err != ErrRetryLimit {
		t.Fatalf("prepared reservation approved: %v", err)
	}
	b.State, b.Transaction = paidState, "0x"+strings.Repeat("ef", 32)
	wrong := b
	wrong.BodyLength++
	if err := s.Complete(ctx, wrong); err == nil {
		t.Fatal("confirmation changed the document")
	}
	if err := s.Complete(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, b); err == nil {
		t.Fatal("paid binding overwritten")
	}
	wrong = b
	wrong.PaymentProofSHA256 = strings.Repeat("00", 32)
	if err := s.ClaimRetry(ctx, wrong, now); err != ErrRetryLimit {
		t.Fatalf("changed proof admitted: %v", err)
	}
	wrong = b
	wrong.BodyLength++
	if err := s.ClaimRetry(ctx, wrong, now); err != ErrRetryLimit {
		t.Fatalf("changed document admitted: %v", err)
	}
	if err := s.ClaimRetry(ctx, b, b.RetryUntil); err != ErrRetryLimit {
		t.Fatalf("expired retry admitted: %v", err)
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ClaimRetry(ctx, b, now)
			if err == nil {
				admitted.Add(1)
			} else if err != ErrRetryLimit {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	stored, err := s.Get(ctx, b.PaymentKey)
	if err != nil || stored == nil {
		t.Fatal("readback", err)
	}
	if admitted.Load() != 3 || stored.RetryCount != 3 || stored.State != paidState || stored.Transaction != b.Transaction || stored.BodyLength != b.BodyLength {
		t.Fatalf("atomic retry state: admitted=%d binding=%+v", admitted.Load(), stored)
	}
	// Existing deployed rows have no state/reservation/counter. They remain
	// immutable paid records and acquire a counter on their first retry.
	b.PaymentKey += ":legacy"
	b.State, b.ReservationID = "", ""
	b.RetryCount = 0
	if err := s.Put(ctx, b); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := s.ClaimRetry(ctx, b, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ClaimRetry(ctx, b, now); err != ErrRetryLimit {
		t.Fatalf("legacy retry cap: %v", err)
	}

	quotaPayer := fmt.Sprintf("synthetic-payer-%d", time.Now().UnixNano())
	quotaKey, quotaExpiry := failureQuotaKey(protocol.Config{}, quotaPayer, now)
	var increments atomic.Int32
	for i := range 24 {
		wg.Add(1)
		go func(event int) {
			defer wg.Done()
			eventID := protocol.SHA256([]byte(fmt.Sprintf("quota-event-%d", event)))
			if err := s.IncrementFailureQuota(ctx, quotaKey, quotaExpiry, eventID, quotaEventUnpaid); err != nil {
				t.Error(err)
				return
			}
			increments.Add(1)
		}(i)
	}
	wg.Wait()
	// Replaying the same Lambda failure event cannot inflate the counter.
	if err := s.IncrementFailureQuota(ctx, quotaKey, quotaExpiry, protocol.SHA256([]byte("quota-event-0")), quotaEventUnpaid); err != nil {
		t.Fatal(err)
	}
	quota, err := s.GetFailureQuota(ctx, quotaKey, now)
	if err != nil || increments.Load() != 24 || quota.Unpaid != 24 || quota.ExpiresAt != quotaExpiry {
		t.Fatalf("atomic failure quota: increments=%d quota=%+v err=%v", increments.Load(), quota, err)
	}
	// Parallel replays of one abandonment must increment only its separate
	// counter, leaving completed-unpaid accounting unchanged in the same row.
	abandonedEvent := protocol.SHA256([]byte("typed-abandonment-event"))
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.IncrementFailureQuota(ctx, quotaKey, quotaExpiry, abandonedEvent, quotaEventAbandoned); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	quota, err = s.GetFailureQuota(ctx, quotaKey, now)
	if err != nil || quota.Unpaid != 24 || quota.Abandonments != 1 || quota.ExpiresAt != quotaExpiry {
		t.Fatalf("atomic mixed resource quota: quota=%+v err=%v", quota, err)
	}
	// A public settled receipt writes abandonments under its payment identity,
	// not the wallet row used to admit independent purchases.
	paidQuotaKey, paidExpiry := paidFailureQuotaKey(protocol.Config{}, quotaPayer, protocol.SHA256([]byte("public settled receipt")), now)
	for i := range FailedParseQuota {
		eventID := protocol.SHA256([]byte(fmt.Sprintf("paid-abandonment-%d", i)))
		if err := s.IncrementFailureQuota(ctx, paidQuotaKey, paidExpiry, eventID, quotaEventAbandoned); err != nil {
			t.Fatal(err)
		}
	}
	paidQuota, err := s.GetFailureQuota(ctx, paidQuotaKey, now)
	if err != nil || paidQuota.Unpaid != 0 || paidQuota.Abandonments != FailedParseQuota || paidQuota.ExpiresAt != paidExpiry {
		t.Fatalf("payment-scoped abandonment quota: quota=%+v err=%v", paidQuota, err)
	}
	walletQuota, err := s.GetFailureQuota(ctx, quotaKey, now)
	if err != nil || walletQuota.Unpaid != 24 || walletQuota.Abandonments != 1 {
		t.Fatalf("payment receipt poisoned wallet quota: quota=%+v err=%v", walletQuota, err)
	}
}
