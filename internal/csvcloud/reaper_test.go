package csvcloud

import (
	"context"
	"testing"
	"time"
)

func TestReaperDurablyBoundsCleanupAttemptsAndDuplicateTicks(t *testing.T) {
	p, j, q, s, w := processorFixture(t)
	w.runFail = true
	_ = p.Process(ctx, j.ID, q)
	p.RecoveryFence = &fenceStub{err: ErrCleanup}
	p.Eraser = s
	now := fixtureTime
	r := Reaper{Repo: p.Repo, RunID: ID(), JobID: j.ID, Now: func() time.Time { return now }, Recover: func(c context.Context, id string) error { return p.Recover(c, id) }}
	if r.Schedule(ctx, now.Add(2*time.Minute).Unix()) != nil {
		t.Fatal("schedule")
	}
	if r.Schedule(ctx, now.Unix()) == nil {
		t.Fatal("duplicate schedule")
	}
	if r.Tick(ctx) != ErrConflict {
		t.Fatal("early tick")
	}
	for i := 0; i < 3; i++ {
		now = fixtureTime.Add(time.Duration(180+i*90) * time.Second)
		p.Now = func() time.Time { return now }
		if r.Tick(ctx) == nil {
			t.Fatal("unknown cleanup marked done")
		}
	}
	v, e := r.read(ctx)
	if e != nil || v.State != "NEEDS_OPERATOR" || v.Attempts != 3 {
		t.Fatal("retry bound", v, e)
	}
	if r.Tick(ctx) != ErrCleanup || w.calls != 1 {
		t.Fatal("work replayed")
	}
	m := p.Repo.Client.(*memoryDynamo)
	if avs(m.rows["CAPACITY"]["used"]) != "1" {
		t.Fatal("released unknown capacity")
	}
}
func TestReaperResumesLostClaimAndReleasesOnlyAfterErasure(t *testing.T) {
	p, j, q, s, w := processorFixture(t)
	w.runFail = true
	_ = p.Process(ctx, j.ID, q)
	p.RecoveryFence = &fenceStub{}
	p.Eraser = s
	now := fixtureTime
	r := Reaper{Repo: p.Repo, RunID: ID(), JobID: j.ID, Now: func() time.Time { return now }, Recover: func(c context.Context, id string) error { return p.Recover(c, id) }}
	_ = r.Schedule(ctx, now.Add(2*time.Minute).Unix())
	now = fixtureTime.Add(3 * time.Minute)
	p.Now = func() time.Time { return now }
	m := p.Repo.Client.(*memoryDynamo)
	m.lost = true
	if r.Tick(ctx) != ErrUnknown {
		t.Fatal("lost reservation should not execute")
	}
	v, _ := r.read(ctx)
	if v.State != "RECOVERING" || v.Attempts != 1 {
		t.Fatal("lost attempt not reserved")
	}
	if r.Tick(ctx) != ErrConflict {
		t.Fatal("lease bypass")
	}
	now = now.Add(91 * time.Second)
	if e := r.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	v, _ = r.read(ctx)
	if v.State != "DONE" || readJob(t, p.Repo, j.ID).Artifact != "ERASED" || avs(m.rows["CAPACITY"]["used"]) != "0" {
		t.Fatal("cleanup evidence missing")
	}
	if r.Tick(ctx) != nil || w.calls != 1 {
		t.Fatal("duplicate cleanup/work")
	}
}
func TestReaperPreservesCommittedReadyResult(t *testing.T) {
	p, j, q, _, _ := processorFixture(t)
	if p.Process(ctx, j.ID, q) != nil {
		t.Fatal("fixture")
	}
	now := fixtureTime
	r := Reaper{Repo: p.Repo, RunID: ID(), JobID: j.ID, Now: func() time.Time { return now }, Recover: func(_ context.Context, _ string) error { t.Fatal("ready result erased"); return nil }}
	_ = r.Schedule(ctx, now.Unix())
	if r.Tick(ctx) != nil {
		t.Fatal("tick")
	}
	v, _ := r.read(ctx)
	if v.State != "RESULT_READY" {
		t.Fatal("result lost")
	}
}

func TestSyntheticRetirementResumesReadyReaperWithoutReprocessing(t *testing.T) {
	p, j, q, s, w := processorFixture(t)
	if p.Process(ctx, j.ID, q) != nil {
		t.Fatal("prepare")
	}
	now := fixtureTime
	r := Reaper{Repo: p.Repo, RunID: ID(), JobID: j.ID, Now: func() time.Time { return now }, Recover: func(c context.Context, id string) error {
		return (Cleanup{Repo: p.Repo, Writers: &fenceStub{}, Objects: s, Gate: Gate{Enabled: true}}).Complete(c, id)
	}}
	if r.Schedule(ctx, now.Unix()) != nil || r.Tick(ctx) != nil {
		t.Fatal("ready reservation")
	}
	controller := Controller{Config: ControllerConfig{JobID: j.ID, SyntheticOnly: true}, Repo: p.Repo}
	if controller.FinishSynthetic(ctx) != nil {
		t.Fatal("retire")
	}
	if r.Tick(ctx) != ErrCleanup {
		t.Fatal("ready reaper not reopened")
	}
	p.Now = func() time.Time { return now }
	if r.Tick(ctx) != nil {
		t.Fatal("cleanup failed")
	}
	got, _ := r.read(ctx)
	if got.State != "DONE" || readJob(t, p.Repo, j.ID).Artifact != "ERASED" || w.calls != 1 {
		t.Fatal("result replayed or not erased")
	}
}
