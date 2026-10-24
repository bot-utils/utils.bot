package csvcloud

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// PrivateUploadCoordinator is an explicitly invoked, bounded private consumer.
// Run starts before admission and polls the durable API_COMPLETE signal. It
// receives a distinct controller identity; it is never assembled in the API.
// It cannot admit fixtures, retry uncertain dispatches, or call payments.
type PrivateUploadCoordinator struct {
	Backend *PrivateRunBackend
	// Retire must use the independent bucket-absence verifier and retain capacity
	// until proof succeeds. It is invoked only after the upload grant and maximum
	// API request lifetime have expired, behind a versioned never-started fence.
	Retire func(context.Context, Job) error
}

func (c PrivateUploadCoordinator) Step(ctx context.Context) (bool, error) {
	b := c.Backend
	if b == nil || !b.valid() {
		return false, ErrDisabled
	}
	j, err := b.Repo.Get(ctx, b.RunID)
	if err != nil {
		return false, err
	}
	if j == nil {
		return false, nil
	}
	if j.Artifact == "ERASED" {
		return true, nil
	}
	if j.IntentBinding != b.Request.Binding() || j.Financial != "UNPAID" {
		return false, ErrIntegrity
	}
	if j.Artifact == "UPLOAD_INCOMPLETE" && b.now() >= j.UploadUntil || j.Artifact == "DELETING" {
		if c.Retire == nil {
			return false, ErrCleanup
		}
		fenced, err := b.fenceUnstarted(ctx, *j)
		if err != nil {
			return false, err
		}
		// An API request can still be completing CreateMultipartUpload after its
		// context deadline. No new work may start behind DELETING. Wait for the
		// maximum API request lifetime as well as all grants, then destroy the unique
		// bucket. The bucket must never be recreated; a late accepted PUT cannot
		// restore access. Capacity remains charged through independent absence proof.
		if b.now() < fenced.UploadUntil+90 {
			return false, nil
		}
		if err := c.Retire(ctx, fenced); err != nil {
			return false, err
		}
		observed, err := b.Repo.Get(ctx, b.RunID)
		if err != nil || observed == nil || observed.Artifact != "ERASED" {
			return false, ErrCleanup
		}
		return true, nil
	}
	if j.Artifact == "QUEUED" {
		if err := b.VerifyAndQueue(ctx, b.RunID); err != nil {
			return false, err
		}
		return true, nil
	}
	if j.Artifact != "UPLOAD_INCOMPLETE" && j.Artifact != "UPLOAD_VERIFIED" {
		return false, ErrConflict
	}
	// No completion signal means no full-file read, multipart completion or queue
	// publication. CREATING rows, including missing UploadId after a lost reply,
	// remain unchanged and eventually take the never-started retirement path.
	var signal struct {
		Version int64
		Binding string
	}
	v, err := b.read(ctx, "API_COMPLETE/"+b.RunID, &signal)
	if err != nil {
		return false, err
	}
	if v == 0 {
		return false, nil
	}
	if v != 1 || signal.Version != v || signal.Binding != j.IntentBinding {
		return false, ErrIntegrity
	}
	for _, o := range j.Inputs {
		u, err := b.upload(ctx, o)
		if err != nil {
			return false, err
		}
		if u.State == "CREATING" {
			return false, nil
		}
	}
	if err := b.VerifyAndQueue(ctx, b.RunID); err != nil {
		return false, err
	}
	return true, nil
}

func (c PrivateUploadCoordinator) Run(ctx context.Context) error {
	if c.Backend == nil || !c.Backend.valid() {
		return ErrDisabled
	}
	// No background daemon, scan, arbitrary job ID, or lifetime extension.
	until := time.Now().Add(10 * time.Minute)
	if expiry := time.Unix(c.Backend.Until, 0); expiry.Before(until) {
		until = expiry
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	cleanupAttempts := 0
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		done, err := c.Step(ctx)
		if err != nil {
			if err != ErrCleanup || c.Retire == nil {
				return err
			}
			j, e := c.Backend.Repo.Get(ctx, c.Backend.RunID)
			cleanupAttempts++
			if e != nil || j == nil || j.Artifact != "DELETING" || cleanupAttempts >= 3 {
				return err
			}
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrUnknown
		case <-tick.C:
		}
	}
}

// fenceUnstarted is deliberately narrower than running-task recovery. No
// dispatch reservation of any kind, transfer, broker record, payment or result
// may exist. The same transaction fences API writes and races with broker intent.
func (b PrivateRunBackend) fenceUnstarted(ctx context.Context, j Job) (Job, error) {
	if j.ID != b.RunID || j.IntentBinding != b.Request.Binding() || j.Financial != "UNPAID" || j.Dispatch != nil || j.TransferStarted || j.Result != nil || j.Settlement != nil || (j.Artifact != "UPLOAD_INCOMPLETE" && j.Artifact != "DELETING") {
		return Job{}, ErrConflict
	}

	if j.Artifact == "DELETING" {
		var marker struct {
			Version, JobVersion, Until int64
			Binding                    string
		}
		v, e := b.read(ctx, "API_RETIRE/"+b.RunID, &marker)
		if e != nil || v != 1 || marker.Version != 1 || marker.JobVersion != j.Version || marker.Until != j.UploadUntil+90 || marker.Binding != j.IntentBinding {
			return Job{}, ErrCleanup
		}
		broker, e := b.Repo.get(ctx, "BROKER/"+b.RunID)
		if e != nil || len(broker) != 0 {
			return Job{}, ErrCleanup
		}
		if _, e = privateDeliveryFence(ctx, b.Repo, j.ID); e != nil {
			return Job{}, e
		}
		return j, nil
	}
	next := copyJob(j)
	next.Version++
	next.Artifact = "DELETING"
	items := []d.TransactWriteItem{b.Repo.versioned(j, next), {ConditionCheck: &d.ConditionCheck{TableName: aws.String(b.Repo.Table), Key: key("BROKER/" + b.RunID), ConditionExpression: aws.String("attribute_not_exists(pk)")}}}
	fence, err := privateDeliveryFence(ctx, b.Repo, j.ID)
	if err != nil {
		return Job{}, err
	}
	items = append(items, d.TransactWriteItem{ConditionCheck: fence})
	marker, _ := json.Marshal(struct {
		Version, JobVersion, Until int64
		Binding                    string
	}{1, next.Version, next.UploadUntil + 90, next.IntentBinding})
	items = append(items, d.TransactWriteItem{Put: &d.Put{TableName: aws.String(b.Repo.Table), Item: map[string]d.AttributeValue{"pk": str("API_RETIRE/" + b.RunID), "version": num(1), "data": &d.AttributeValueMemberB{Value: marker}}, ConditionExpression: aws.String("attribute_not_exists(pk)")}})
	if err = b.Repo.txn(ctx, items); err != nil {
		return Job{}, err
	}
	return next, nil
}
