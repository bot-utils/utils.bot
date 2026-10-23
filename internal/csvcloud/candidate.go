package csvcloud

import (
	"context"
	"io"
	"time"
)

// The private broker can write candidates but cannot read result objects.
// Publication belongs to the independently credentialed controller.
type privateCandidateStorage struct{ Storage }

func (s privateCandidateStorage) PutResult(ctx context.Context, m Manifest, data io.Reader) (Manifest, error) {
	return s.Storage.putCandidate(ctx, m, data)
}

func (r Repository) stageCandidate(ctx context.Context, old Job, m Manifest) (Job, error) {
	if !r.Gate.Enabled {
		return old, ErrDisabled
	}
	if !old.valid() || old.Artifact != "RUNNING" || old.Financial != "UNPAID" || !old.WorkerStopped || !old.TransferStarted || old.Candidate != nil || old.Result != nil || !m.Valid() || m.Object.JobID != old.ID {
		return old, ErrConflict
	}
	next := copyJob(old)
	next.Version++
	next.Candidate = &m
	return next, r.advanceVerified(ctx, old, next)
}

// FinalizeCandidate independently proves original worker/ENI absence and reads
// the stored gzip candidate before publishing any result or payment challenge.
// Unverified candidates remain unpaid and are recoverable by the ordinary reaper.
func (c Controller) FinalizeCandidate(ctx context.Context) error {
	if !c.Config.SyntheticOnly {
		return ErrDisabled
	}
	j, err := c.Repo.Get(ctx, c.Config.JobID)
	if err != nil || j == nil {
		return ErrUnknown
	}
	if j.Candidate == nil {
		return nil
	}
	if time.Now().Unix() >= j.TransferUntil || j.Artifact != "RUNNING" || j.Financial != "UNPAID" || !j.WorkerStopped || j.Dispatch == nil || j.Dispatch.TaskARN != c.Config.Worker.TaskARN || c.Results == nil || c.candidateWitness == nil {
		return ErrConflict
	}
	if c.candidateWitness(ctx) != nil {
		return ErrCleanup
	}
	artifacts := Artifacts{Repo: c.Repo, Results: c.Results, Gate: Gate{Enabled: true}}
	return artifacts.PublishResult(ctx, j.ID, j.Dispatch.Token, *j.Candidate, time.Now().Add(30*time.Minute).Unix())
}
