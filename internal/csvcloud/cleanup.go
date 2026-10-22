package csvcloud

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// WriterFence must independently prove that the original task is stopped and
// all upload/write capabilities have expired or been revoked, including requests
// already in flight. No production implementation is enabled in this package.
type WriterFence interface {
	VerifyStopped(context.Context, Job) error
}
type Eraser interface {
	EraseAndVerify(context.Context, Job) error
}
type Cleanup struct {
	Repo    Repository
	Writers WriterFence
	Objects Eraser
	Gate    Gate
}

func (c Cleanup) Complete(ctx context.Context, id string) error {
	if !c.Gate.Enabled {
		return ErrDisabled
	}
	j, e := c.Repo.Get(ctx, id)
	if e != nil || j == nil {
		return ErrConflict
	}
	if j.Artifact == "ERASED" {
		return nil
	}
	if j.Artifact != "DELETING" || j.Financial == "SETTLEMENT_PENDING" || c.Writers == nil || c.Objects == nil {
		return ErrCleanup
	}
	if c.Writers.VerifyStopped(ctx, *j) != nil || c.Objects.EraseAndVerify(ctx, *j) != nil {
		return ErrCleanup
	}
	return c.Repo.erased(ctx, *j)
}

// erased is private: only Cleanup can release a job's active capacity after both
// fences. The CAS and decrement commit together, so repeated cleanup is harmless.
func (r Repository) erased(ctx context.Context, old Job) error {
	if !old.valid() || old.Artifact != "DELETING" || old.DownloadLease != "" {
		return ErrCleanup
	}
	next := Job{ID: old.ID, Version: old.Version + 1, Artifact: "ERASED", Financial: old.Financial, RecoveryVerifier: old.RecoveryVerifier, Settlement: old.Settlement, Remedy: old.Remedy}
	if !next.valid() {
		return ErrInvalid
	}
	items := []d.TransactWriteItem{r.versioned(old, next), {Update: &d.Update{TableName: aws.String(r.Table), Key: key("CAPACITY"), UpdateExpression: aws.String("SET #used = #used - :one"), ConditionExpression: aws.String("#used >= :one"), ExpressionAttributeNames: map[string]string{"#used": "used"}, ExpressionAttributeValues: map[string]d.AttributeValue{":one": num(1)}}}}
	for _, pk := range []string{"IDEMPOTENCY/" + old.IdempotencyHash, "NONCE/" + old.AdmissionNonceHash} {
		items = append(items, d.TransactWriteItem{Update: &d.Update{TableName: aws.String(r.Table), Key: key(pk), UpdateExpression: aws.String("REMOVE #binding"), ConditionExpression: aws.String("#job = :job"), ExpressionAttributeNames: map[string]string{"#job": "job", "#binding": "binding"}, ExpressionAttributeValues: map[string]d.AttributeValue{":job": str(old.ID)}}})
	}
	return r.txn(ctx, items)
}
