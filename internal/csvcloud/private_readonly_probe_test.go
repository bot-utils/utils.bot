package csvcloud

import (
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
