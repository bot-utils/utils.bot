package csvcloud

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type RecoveryRecord struct {
	LeaseToken, JobID, RunID, State            string
	Version, Due, NotBefore, LeaseUntil, Until int64
	Attempts                                   int
}

// Reaper is the private scheduled-controller entrypoint. One durable job key,
// three cleanup attempts, a 90-second lease (>45s Recover limit), ten-minute
// execution window, and no calls to dispatch, process, quotes or settlement.
type Reaper struct {
	Repo         Repository
	RunID, JobID string
	Now          func() time.Time
	Recover      func(context.Context, string) error
}

func (r Reaper) now() int64 {
	if r.Now != nil {
		return r.Now().Unix()
	}
	return time.Now().Unix()
}
func (r Reaper) read(ctx context.Context) (RecoveryRecord, error) {
	row, e := r.Repo.get(ctx, "RECOVERY/"+r.JobID)
	if e != nil {
		return RecoveryRecord{}, e
	}
	var v RecoveryRecord
	b, ok := row["data"].(*d.AttributeValueMemberB)
	if !ok || strictProof(b.Value, &v) != nil || v.JobID != r.JobID || v.RunID != r.RunID || v.Version < 1 || v.Attempts < 0 || v.Attempts > 3 || v.NotBefore <= 0 || v.Until <= v.NotBefore || v.Until-v.NotBefore > 600 || v.Due < v.NotBefore {
		return v, ErrCleanup
	}
	return v, nil
}
func (r Reaper) save(ctx context.Context, old *RecoveryRecord, next RecoveryRecord) error {
	raw, _ := json.Marshal(next)
	condition := "attribute_not_exists(pk)"
	var values map[string]d.AttributeValue
	var names map[string]string
	if old != nil {
		condition = "#v = :v"
		values = map[string]d.AttributeValue{":v": num(old.Version)}
		names = map[string]string{"#v": "version"}
	}
	return r.Repo.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(r.Repo.Table), Item: map[string]d.AttributeValue{"pk": str("RECOVERY/" + r.JobID), "version": num(next.Version), "data": &d.AttributeValueMemberB{Value: raw}, "due": num(next.Due)}, ConditionExpression: aws.String(condition), ExpressionAttributeNames: names, ExpressionAttributeValues: values}}})
}
func (r Reaper) Schedule(ctx context.Context, due int64) error {
	if !r.Repo.Gate.Enabled {
		return ErrDisabled
	}
	now := r.now()
	if !opaque(r.RunID) || !opaque(r.JobID) || due < now || due > now+120 {
		return ErrInvalid
	}
	return r.save(ctx, nil, RecoveryRecord{JobID: r.JobID, RunID: r.RunID, Version: 1, Due: due, NotBefore: due, Until: now + 600, State: "PENDING"})
}
func (r Reaper) Tick(ctx context.Context) error {
	if !r.Repo.Gate.Enabled {
		return ErrDisabled
	}
	if r.Recover == nil {
		return ErrInvalid
	}
	v, e := r.read(ctx)
	if e != nil {
		return e
	}
	if v.State == "DONE" {
		return nil
	}
	if v.State == "RESULT_READY" {
		// An explicit synthetic retirement may commit after this terminal record.
		// Resume only deletion, never processing or a settlement-bearing result.
		job, e := r.Repo.Get(ctx, r.JobID)
		if e != nil || job == nil {
			return ErrUnknown
		}
		if job.Artifact != "DELETING" || job.Financial != "AWAITING_PAYMENT" || job.Settlement != nil {
			return nil
		}
		next := v
		next.Version++
		next.State = "PENDING"
		next.Due = r.now()
		if next.Due < next.NotBefore {
			next.Due = next.NotBefore
		}
		if e = r.save(ctx, &v, next); e != nil {
			return ErrUnknown
		}
		return ErrCleanup
	}
	if v.State == "NEEDS_OPERATOR" {
		return ErrCleanup
	}
	now := r.now()
	if now < v.Due || now < v.LeaseUntil {
		return ErrConflict
	}
	if v.State != "PENDING" && v.State != "RECOVERING" {
		return ErrCleanup
	}
	next := v
	next.Version++
	if now >= v.Until || v.Attempts >= 3 {
		next.State = "NEEDS_OPERATOR"
		_ = r.save(ctx, &v, next)
		return ErrCleanup
	}
	next.Attempts++
	next.LeaseToken = ID()
	next.State = "RECOVERING"
	next.LeaseUntil = now + 90
	if e = r.save(ctx, &v, next); e != nil {
		return e
	}
	// Publication that committed before an unknown reply remains eligible.
	job, e := r.Repo.Get(ctx, r.JobID)
	if e != nil || job == nil {
		return ErrUnknown
	}
	if job.Artifact == "RESULT_PREPARED" && job.Financial == "AWAITING_PAYMENT" {
		final := next
		final.Version++
		final.State = "RESULT_READY"
		final.LeaseUntil = 0
		return r.save(ctx, &next, final)
	}
	operation, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	failure := r.Recover(context.WithValue(operation, recoveryLeaseKey{}, recoveryLease{Version: next.Version, Token: next.LeaseToken}), r.JobID)
	final := next
	final.Version++
	final.LeaseUntil = 0
	final.Due = now + 90
	job, e = r.Repo.Get(ctx, r.JobID)
	if failure == nil && e == nil && job != nil && job.Artifact == "ERASED" {
		final.State = "DONE"
	} else if next.Attempts >= 3 || r.now() >= v.Until {
		final.State = "NEEDS_OPERATOR"
	} else {
		final.State = "PENDING"
	}
	if e = r.save(ctx, &next, final); e != nil {
		return ErrUnknown
	}
	if final.State != "DONE" {
		return ErrCleanup
	}
	return nil
}

type recoveryLeaseKey struct{}
type recoveryLease struct {
	Version int64
	Token   string
}
