package csvcloud

import (
	"context"
	"encoding/json"
	"errors"
	"pdfservice/internal/jsonwire"
	"reflect"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}
type Repository struct {
	Client DynamoAPI
	Table  string
	Gate   Gate
}

func str(v string) d.AttributeValue            { return &d.AttributeValueMemberS{Value: v} }
func num(v int64) d.AttributeValue             { return &d.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)} }
func key(v string) map[string]d.AttributeValue { return map[string]d.AttributeValue{"pk": str(v)} }
func (r Repository) get(ctx context.Context, pk string) (map[string]d.AttributeValue, error) {
	if !r.Gate.Enabled {
		return nil, ErrDisabled
	}
	out, err := r.Client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(r.Table), Key: key(pk), ConsistentRead: aws.Bool(true)}, func(o *dynamodb.Options) { o.RetryMaxAttempts = 1 })
	if err != nil {
		privateDependencyFailure("dynamodb_get", err)
		return nil, ErrUnknown
	}
	return out.Item, nil
}
func (r Repository) Get(ctx context.Context, id string) (*Job, error) {
	if !opaque(id) {
		return nil, ErrInvalid
	}
	item, err := r.get(ctx, "JOB/"+id)
	if err != nil {
		return nil, err
	}
	if len(item) == 0 {
		return nil, nil
	}
	v, ok := item["data"].(*d.AttributeValueMemberB)
	if !ok || len(v.Value) > MaxMetadata {
		return nil, ErrInvalid
	}
	var j Job
	if jsonwire.Decode(v.Value, &j, MaxMetadata) != nil || !j.valid() || j.ID != id {
		return nil, ErrInvalid
	}
	version, vok := item["version"].(*d.AttributeValueMemberN)
	artifact, aok := item["artifact"].(*d.AttributeValueMemberS)
	financial, fok := item["financial"].(*d.AttributeValueMemberS)
	if !vok || !aok || !fok || version.Value != strconv.FormatInt(j.Version, 10) || artifact.Value != j.Artifact || financial.Value != j.Financial {
		return nil, ErrInvalid
	}
	return &j, nil
}
func row(j Job) map[string]d.AttributeValue {
	raw, _ := json.Marshal(j)
	return map[string]d.AttributeValue{"pk": str("JOB/" + j.ID), "version": num(j.Version), "artifact": str(j.Artifact), "financial": str(j.Financial), "data": &d.AttributeValueMemberB{Value: raw}}
}
func (r Repository) put(j Job, condition string, values map[string]d.AttributeValue) d.TransactWriteItem {
	return d.TransactWriteItem{Put: &d.Put{TableName: aws.String(r.Table), Item: row(j), ConditionExpression: aws.String(condition), ExpressionAttributeValues: values}}
}
func (r Repository) txn(ctx context.Context, items []d.TransactWriteItem) error {
	if !r.Gate.Enabled {
		return ErrDisabled
	}
	_, err := r.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}, func(o *dynamodb.Options) { o.RetryMaxAttempts = 1 })
	var canceled *d.TransactionCanceledException
	if errors.As(err, &canceled) {
		return ErrConflict
	}
	if err != nil {
		return ErrUnknown
	}
	return nil
}

// Create reserves capacity and binds the verified admission nonce and recovery
// identity atomically. No TTL is placed on financial/idempotency records.
func (r Repository) Create(ctx context.Context, j Job, maximum int64) error {
	if !j.valid() || j.Version != 1 || j.Artifact != "UPLOAD_INCOMPLETE" || j.Financial != "UNPAID" || j.Result != nil || j.Settlement != nil || j.Dispatch != nil || maximum < 1 || maximum > 2 {
		return ErrInvalid
	}
	items := []d.TransactWriteItem{r.put(j, "attribute_not_exists(pk)", nil)}
	for _, pk := range []string{"IDEMPOTENCY/" + j.IdempotencyHash, "NONCE/" + j.AdmissionNonceHash} {
		items = append(items, d.TransactWriteItem{Put: &d.Put{TableName: aws.String(r.Table), Item: map[string]d.AttributeValue{"pk": str(pk), "job": str(j.ID), "binding": str(j.IntentBinding)}, ConditionExpression: aws.String("attribute_not_exists(pk)")}})
	}
	items = append(items, d.TransactWriteItem{Update: &d.Update{TableName: aws.String(r.Table), Key: key("CAPACITY"), ExpressionAttributeNames: map[string]string{"#used": "used"}, UpdateExpression: aws.String("SET #used = if_not_exists(#used, :zero) + :one"), ConditionExpression: aws.String("attribute_not_exists(#used) OR #used < :max"), ExpressionAttributeValues: map[string]d.AttributeValue{":zero": num(0), ":one": num(1), ":max": num(maximum)}}})
	err := r.txn(ctx, items)
	if err == nil {
		return nil
	}
	old, readErr := r.Get(ctx, j.ID)
	if readErr == nil && old != nil && sameJob(*old, j) {
		return nil
	}
	return err
}

// Replace is deliberately limited to challenge updates and marking deletion.
// Evidence-bearing lifecycle and download changes use their dedicated methods.
func (r Repository) Replace(ctx context.Context, old, next Job) error {
	if !validReplacement(old, next) || old.Artifact != next.Artifact && next.Artifact != "DELETING" {
		return ErrInvalid
	}
	permitted := copyJob(old)
	permitted.Version = next.Version
	permitted.Quote = next.Quote
	permitted.QuoteCount = next.QuoteCount
	permitted.Artifact = next.Artifact
	permitted.Remedy = next.Remedy
	if !reflect.DeepEqual(permitted, next) {
		return ErrInvalid
	}
	return r.advanceVerified(ctx, old, next)
}

// advanceVerified is private to the evidence-checking operations in this package.
func (r Repository) advanceVerified(ctx context.Context, old, next Job) error {
	if !validReplacement(old, next) {
		return ErrInvalid
	}
	return r.txn(ctx, []d.TransactWriteItem{r.versioned(old, next)})
}

// versioned uses a non-reserved attribute name and preserves a strict CAS fence.
func (r Repository) versioned(old, next Job) d.TransactWriteItem {
	item := r.put(next, "#v = :v", map[string]d.AttributeValue{":v": num(old.Version)})
	item.Put.ExpressionAttributeNames = map[string]string{"#v": "version"}
	return item
}
func (r Repository) Queue(ctx context.Context, old Job, token string, reserveMicroUSD, maximumMicroUSD int64) (Job, error) {
	next := old
	if !old.valid() || old.Artifact != "UPLOAD_VERIFIED" || old.Dispatch != nil || !opaque(token) || reserveMicroUSD <= 0 || maximumMicroUSD < reserveMicroUSD {
		return next, ErrInvalid
	}
	next.Version++
	next.Artifact = "QUEUED"
	next.Dispatch = &Dispatch{Token: token, State: "RESERVED", ReservedMicroUSD: reserveMicroUSD}
	items := []d.TransactWriteItem{r.versioned(old, next), {Put: &d.Put{TableName: aws.String(r.Table), Item: map[string]d.AttributeValue{"pk": str("OUTBOX/" + old.ID), "token": str(token), "state": str("PENDING")}, ConditionExpression: aws.String("attribute_not_exists(pk)")}}, {Update: &d.Update{TableName: aws.String(r.Table), Key: key("BUDGET"), ExpressionAttributeNames: map[string]string{"#reserved": "reserved"}, UpdateExpression: aws.String("SET #reserved = if_not_exists(#reserved, :zero) + :cost"), ConditionExpression: aws.String("attribute_not_exists(#reserved) OR #reserved <= :remaining"), ExpressionAttributeValues: map[string]d.AttributeValue{":zero": num(0), ":cost": num(reserveMicroUSD), ":remaining": num(maximumMicroUSD - reserveMicroUSD)}}}}
	return next, r.txn(ctx, items)
}
func (r Repository) ReserveSettlement(ctx context.Context, old Job, s Settlement, nonceKey string) (Job, error) {
	next := old
	if !old.valid() || old.Artifact != "RESULT_PREPARED" || old.Financial != "AWAITING_PAYMENT" || old.Result == nil || !old.Result.Valid() || old.Settlement != nil || !opaque(s.ID) || !opaque(nonceKey) || nonceKey == old.AdmissionNonceHash {
		return next, ErrConflict
	}
	next.Version++
	next.Financial = "SETTLEMENT_PENDING"
	s.State = "SETTLEMENT_PENDING"
	next.Settlement = &s
	if !validReplacement(old, next) {
		return old, ErrInvalid
	}
	return next, r.txn(ctx, []d.TransactWriteItem{r.versioned(old, next), {Put: &d.Put{TableName: aws.String(r.Table), Item: map[string]d.AttributeValue{"pk": str("NONCE/" + nonceKey), "job": str(old.ID), "reservation": str(s.ID)}, ConditionExpression: aws.String("attribute_not_exists(pk)")}}})
}
func (r Repository) ReserveDownload(ctx context.Context, old Job, attempt string, start, end, now int64) (Job, error) {
	next := old
	bytes := end - start + 1
	if !old.valid() || old.Result == nil || !old.Result.Valid() || old.Financial != "PAID" || old.Artifact != "RETRIEVABLE" || now >= old.ResultUntil || old.DownloadLease != "" || !opaque(attempt) || start < 0 || end < start || end >= old.Result.Object.Bytes || bytes > 3*old.Result.Object.Bytes-old.DownloadUsed {
		return next, ErrConflict
	}
	next.Version++
	next.DownloadUsed += bytes
	next.DownloadLease = attempt
	next.DownloadUntil = now + 90
	next.DownloadStart = start
	next.DownloadEnd = end
	next.DownloadClaimed = false
	if !validReplacement(old, next) {
		return old, ErrInvalid
	}
	return next, r.txn(ctx, []d.TransactWriteItem{r.versioned(old, next), {Put: &d.Put{TableName: aws.String(r.Table), Item: map[string]d.AttributeValue{"pk": str("DOWNLOAD/" + old.ID + "/" + attempt), "bytes": num(bytes), "start": num(start), "end": num(end)}, ConditionExpression: aws.String("attribute_not_exists(pk)")}}, {Update: &d.Update{TableName: aws.String(r.Table), Key: key("DOWNLOAD_CAPACITY"), ExpressionAttributeNames: map[string]string{"#used": "used"}, UpdateExpression: aws.String("SET #used = if_not_exists(#used, :zero) + :one"), ConditionExpression: aws.String("attribute_not_exists(#used) OR #used < :max"), ExpressionAttributeValues: map[string]d.AttributeValue{":zero": num(0), ":one": num(1), ":max": num(2)}}}})
}
func (r Repository) ClaimDownload(ctx context.Context, old Job, now int64) (*DownloadPermit, error) {
	if old.DownloadLease == "" || old.DownloadClaimed || old.DownloadUntil <= now || old.ResultUntil <= now || old.Financial != "PAID" || old.Artifact != "RETRIEVABLE" {
		return nil, ErrConflict
	}
	next := old
	next.Version++
	next.DownloadClaimed = true
	if err := r.advanceVerified(ctx, old, next); err != nil {
		return nil, err
	}
	return &DownloadPermit{job: next}, nil
}

// FinishDownload requires the broker to have closed its stream. A crashed or
// uncertain broker must be reconciled before releasing global stream capacity.
func (r Repository) FinishDownload(ctx context.Context, old Job, lease string) error {
	if old.DownloadLease != lease || !opaque(lease) {
		return ErrConflict
	}
	next := old
	next.Version++
	next.DownloadLease = ""
	next.DownloadUntil = 0
	return r.txn(ctx, []d.TransactWriteItem{r.versioned(old, next), {Update: &d.Update{TableName: aws.String(r.Table), Key: key("DOWNLOAD_CAPACITY"), ExpressionAttributeNames: map[string]string{"#used": "used"}, UpdateExpression: aws.String("SET #used = #used - :one"), ConditionExpression: aws.String(" #used >= :one"), ExpressionAttributeValues: map[string]d.AttributeValue{":one": num(1)}}}})
}
