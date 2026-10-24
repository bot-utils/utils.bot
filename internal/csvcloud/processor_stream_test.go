package csvcloud

import (
	"bytes"
	"context"
	"io"
	"os"
	"pdfservice/internal/csvwire"
	"testing"
	"time"
)

type privateStreamTestWorker struct {
	t            *testing.T
	calls, stops int
	corrupt      bool
	store        *processingStore
}

func (w *privateStreamTestWorker) Run(_ context.Context, _ Dispatch, q csvwire.Request, in map[string]io.Reader, out io.Writer) (csvwire.Result, error) {
	w.calls++
	var request, result bytes.Buffer
	if e := csvwire.WriteRequest(&request, q, in); e != nil {
		return csvwire.Result{}, e
	}
	spool, e := os.CreateTemp(w.t.TempDir(), "parser-spool")
	if e != nil {
		return csvwire.Result{}, e
	}
	defer spool.Close()
	if e = csvwire.ProcessStream(&request, &result, spool); e != nil {
		return csvwire.Result{}, e
	}
	m, e := csvwire.ReadStreamResult(&result, out)
	if w.corrupt {
		m.Rows++
	}
	return m, e
}
func (w *privateStreamTestWorker) StopAndVerify(context.Context, Dispatch) error {
	w.stops++
	if w.store.put != 0 {
		w.t.Fatal("published before stop proof")
	}
	return nil
}
func TestPrivateStreamProcessorStagesOnlyAfterVerificationAndStop(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			f := newPrivateBackendFixture(t)
			if _, e := f.b.Begin(ctx, f.b.Request); e != nil {
				t.Fatal(e)
			}
			if e := f.b.Complete(ctx, f.b.RunID); e != nil {
				t.Fatal(e)
			}
			if e := f.b.VerifyAndQueue(ctx, f.b.RunID); e != nil {
				t.Fatal(e)
			}
			j := startQueued(t, f.b.Repo, readJob(t, f.b.Repo, f.b.RunID))
			// Version participates in intent binding; construct a separate pinned v2 job.
			q := f.b.Request
			q.Version = 2
			repo, _ := memoryRepo()
			j.ID = ID()
			j.IntentBinding = q.Binding()
			j.Version = 1
			j.Artifact = "UPLOAD_INCOMPLETE"
			j.Dispatch = nil
			for i := range j.Inputs {
				j.Inputs[i].JobID = j.ID
				j.Inputs[i].ETag = ""
			}
			seed(t, repo, j)
			if e := (Artifacts{Repo: repo, Inputs: inputStub{}, Gate: Gate{Enabled: true}, Now: func() time.Time { return fixtureTime }}).AcceptUploads(ctx, j.ID); e != nil {
				t.Fatal(e)
			}
			queued, e := repo.Queue(ctx, readJob(t, repo, j.ID), ID(), 100, 100)
			if e != nil {
				t.Fatal(e)
			}
			j = startQueued(t, repo, queued)
			store := &processingStore{data: map[string][]byte{"file": f.data}}
			worker := &privateStreamTestWorker{t: t, corrupt: corrupt, store: store}
			spool, e := os.CreateTemp(t.TempDir(), "candidate-spool")
			if e != nil {
				t.Fatal(e)
			}
			p := Processor{Repo: repo, Objects: store, Worker: worker, Gate: Gate{Enabled: true}, StageResults: true, Now: func() time.Time { return fixtureTime }, StreamSpool: func() (io.ReadWriteSeeker, io.Closer, error) { return spool, spool, nil }}
			e = p.Process(ctx, j.ID, q)
			observed := readJob(t, repo, j.ID)
			if corrupt {
				if e == nil || store.put != 0 || observed.Candidate != nil || observed.Artifact != "PROCESSING_UNKNOWN" {
					t.Fatal("corrupt stream published", e)
				}
			} else {
				if e != nil || store.put != 1 || observed.Candidate == nil || observed.Result != nil || observed.Financial != "UNPAID" {
					t.Fatal("stream staging", e)
				}
			}
			if worker.calls != 1 || worker.stops != 1 {
				t.Fatal("worker repeated")
			}
			if _, e = spool.Stat(); e == nil {
				t.Fatal("staging descriptor leaked")
			}
		})
	}
}
