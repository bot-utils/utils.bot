package csvcloud

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestWriteOnlyBrokerStagesUnpaidCandidateForIndependentController(t *testing.T) {
	p, j, q, _, _ := processorFixture(t)
	p.StageResults = true
	if err := p.Process(ctx, j.ID, q); err != nil {
		t.Fatal(err)
	}
	staged := readJob(t, p.Repo, j.ID)
	if staged.Candidate == nil || staged.Result != nil || staged.Financial != "UNPAID" || staged.Artifact != "RUNNING" || !staged.WorkerStopped {
		t.Fatal("unverified candidate published")
	}
	if _, err := p.Repo.ReserveDownload(ctx, staged, ID(), 0, 0, fixtureTime.Unix()); err != ErrConflict {
		t.Fatal("candidate download allowed", err)
	}
	verifier := &fakeVerifier{}
	controller := Controller{Config: ControllerConfig{SyntheticOnly: true, JobID: j.ID, Worker: StoppedObserver{TaskARN: staged.Dispatch.TaskARN}}, Repo: p.Repo, Results: verifier, candidateWitness: func(context.Context) error { return nil }}
	if err := controller.FinalizeCandidate(ctx); err != nil {
		t.Fatal(err)
	}
	ready := readJob(t, p.Repo, j.ID)
	if ready.Candidate != nil || ready.Result == nil || ready.Artifact != "RESULT_PREPARED" || ready.Financial != "AWAITING_PAYMENT" || verifier.calls.Load() != 1 {
		t.Fatal("independent publication missing")
	}
	if err := controller.FinalizeCandidate(ctx); err != nil || verifier.calls.Load() != 1 {
		t.Fatal("publication replay")
	}
}
func TestCandidatePublicationRejectsMissingWitnessCorruptionAndDrift(t *testing.T) {
	for _, scenario := range []string{"no_witness", "worker_unknown", "corrupt_result", "manifest_drift"} {
		t.Run(scenario, func(t *testing.T) {
			p, j, q, _, _ := processorFixture(t)
			p.StageResults = true
			if err := p.Process(ctx, j.ID, q); err != nil {
				t.Fatal(err)
			}
			staged := readJob(t, p.Repo, j.ID)
			verifier := &fakeVerifier{}
			c := Controller{Config: ControllerConfig{SyntheticOnly: true, JobID: j.ID, Worker: StoppedObserver{TaskARN: staged.Dispatch.TaskARN}}, Repo: p.Repo, Results: verifier, candidateWitness: func(context.Context) error { return nil }}
			switch scenario {
			case "no_witness":
				c.candidateWitness = nil
			case "worker_unknown":
				c.candidateWitness = func(context.Context) error { return ErrCleanup }
			case "corrupt_result":
				verifier.fail = true
			case "manifest_drift":
				changed := *staged.Candidate
				changed.Object.SHA256 = ID()
				if _, err := p.Repo.publishResult(ctx, staged, changed, fixtureTime.Unix()+100); err == nil {
					t.Fatal("candidate identity replaced")
				}
				return
			}
			if c.FinalizeCandidate(ctx) == nil {
				t.Fatal("unverified candidate accepted")
			}
			got := readJob(t, p.Repo, j.ID)
			if got.Result != nil || got.Financial != "UNPAID" || got.Candidate == nil {
				t.Fatal("failure changed publication")
			}
		})
	}
}

func TestWriteOnlyCandidateStorageNeverReadsResult(t *testing.T) {
	m, data := manifest(ID())
	calls := 0
	s := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPut || req.Header.Get("If-None-Match") != "*" || req.Header.Get("X-Amz-Server-Side-Encryption") != "AES256" {
			t.Fatal("unexpected candidate request")
		}
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			t.Fatal(err)
		}
		return response(200, "", http.Header{"Etag": []string{m.Object.ETag}}), nil
	}))
	got, err := (privateCandidateStorage{s}).PutResult(ctx, m, bytes.NewReader(data))
	if err != nil || calls != 1 || got.Object.ETag != m.Object.ETag {
		t.Fatal("candidate store read or failed", err, calls)
	}
}
func TestCandidateCannotPublishAfterTransferWindow(t *testing.T) {
	p, j, q, _, _ := processorFixture(t)
	p.StageResults = true
	p.Now = func() time.Time { return time.Now().Add(-3 * time.Minute) }
	if err := p.Process(ctx, j.ID, q); err != nil {
		t.Fatal(err)
	}
	staged := readJob(t, p.Repo, j.ID)
	verifier := &fakeVerifier{}
	c := Controller{Config: ControllerConfig{SyntheticOnly: true, JobID: j.ID, Worker: StoppedObserver{TaskARN: staged.Dispatch.TaskARN}}, Repo: p.Repo, Results: verifier, candidateWitness: func(context.Context) error { return nil }}
	if c.FinalizeCandidate(ctx) == nil || verifier.calls.Load() != 0 {
		t.Fatal("expired candidate publication allowed")
	}
}
