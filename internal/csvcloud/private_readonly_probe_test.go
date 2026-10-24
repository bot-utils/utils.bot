package csvcloud

import (
	"encoding/json"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"testing"
	"time"
)

func TestPrivateReadOnlyProbeReadsExpiredMetadataWithoutEffects(t *testing.T) {
	f := newPrivateBackendFixture(t)
	if _, err := f.b.Begin(ctx, f.b.Request); err != nil {
		t.Fatal(err)
	}
	transactions := len(f.db.transactions)
	creates := f.creates
	f.b.Now = func() time.Time { return fixtureTime.Add(600 * time.Second) }
	p := privateReadOnlyProbe{runs: PrivateBackendSet{f.b.RunID: f.b}}
	status, err := p.Status(ctx, f.b.RunID)
	if err != nil || status.State != "UPLOAD_METADATA_VERIFIED" {
		t.Fatal("read-only probe failed", err)
	}
	if _, err = p.Begin(ctx, f.b.Request); err != ErrDisabled {
		t.Fatal("admission enabled")
	}
	if p.Complete(ctx, f.b.RunID) != ErrDisabled || p.SimulatePayment(ctx, f.b.RunID) != ErrDisabled || p.Cancel(ctx, f.b.RunID) != ErrDisabled {
		t.Fatal("mutation enabled")
	}
	if _, err = p.Download(ctx, f.b.RunID); err != ErrDisabled {
		t.Fatal("download enabled")
	}
	if len(f.db.transactions) != transactions || f.creates != creates || f.completes != 0 || f.gets != 0 || f.queue.calls != 0 {
		t.Fatal("probe produced effects")
	}
	if _, err = p.Status(ctx, ID()); err != ErrInvalid {
		t.Fatal("unlisted scope probed")
	}
	f.b.Now = func() time.Time { return fixtureTime }
	if _, err = p.Status(ctx, f.b.RunID); err != ErrConflict {
		t.Fatal("active upload probed")
	}
}

func TestPrivateReadOnlyProbeRejectsCreatingMetadataWithoutEffects(t *testing.T) {
	f := newPrivateBackendFixture(t)
	if _, err := f.b.Begin(ctx, f.b.Request); err != nil {
		t.Fatal(err)
	}
	job, err := f.b.job(ctx, f.b.RunID)
	if err != nil {
		t.Fatal(err)
	}
	object := job.Inputs[0]
	record, err := f.b.upload(ctx, object)
	if err != nil {
		t.Fatal(err)
	}
	record.State = "CREATING"
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	row := f.db.rows["API_UPLOAD/"+object.ID]
	row["data"] = &d.AttributeValueMemberB{Value: raw}
	transactions, creates := len(f.db.transactions), f.creates
	f.b.Now = func() time.Time { return fixtureTime.Add(600 * time.Second) }
	p := privateReadOnlyProbe{runs: PrivateBackendSet{f.b.RunID: f.b}}
	if _, err := p.Status(ctx, f.b.RunID); err != ErrIntegrity {
		t.Fatal("creating upload accepted", err)
	}
	if len(f.db.transactions) != transactions || f.creates != creates || f.completes != 0 || f.gets != 0 || f.queue.calls != 0 {
		t.Fatal("probe produced effects")
	}
}
