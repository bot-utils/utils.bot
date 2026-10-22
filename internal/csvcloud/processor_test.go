package csvcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	tabular "pdfservice/internal/csvtabular"
	"pdfservice/internal/csvwire"
	"strings"
	"testing"
	"time"
)

type processingStore struct {
	data     map[string][]byte
	put      int
	manifest Manifest
	out      []byte
}

func (s *processingStore) OpenInput(_ context.Context, o Object) (io.ReadCloser, error) {
	v, ok := s.data[o.Slot]
	if !ok {
		return nil, ErrIntegrity
	}
	return io.NopCloser(bytes.NewReader(v)), nil
}
func (s *processingStore) PutResult(_ context.Context, m Manifest, r io.Reader) (Manifest, error) {
	s.put++
	v, e := io.ReadAll(r)
	if e != nil || Hash(v) != m.Object.SHA256 {
		return m, ErrIntegrity
	}
	m.Object.ETag = `"verified"`
	s.manifest = m
	s.out = v
	return m, nil
}

type processingWorker struct {
	calls, stops      int
	stopFail, corrupt bool
}

func (w *processingWorker) Run(_ context.Context, _ Dispatch, q csvwire.Request, in map[string]io.Reader, out io.Writer) (csvwire.Result, error) {
	w.calls++
	var request, result bytes.Buffer
	if e := csvwire.WriteRequest(&request, q, in); e != nil {
		return csvwire.Result{}, e
	}
	if e := csvwire.Process(&request, &result); e != nil {
		return csvwire.Result{}, e
	}
	m, e := csvwire.ReadResult(&result, out)
	if w.corrupt {
		m.LogicalSHA256 = ID()
	}
	return m, e
}
func (w *processingWorker) StopAndVerify(context.Context, Dispatch) error {
	w.stops++
	if w.stopFail {
		return ErrCleanup
	}
	return nil
}
func processorFixture(t *testing.T) (Processor, Job, csvwire.Request, *processingStore, *processingWorker) {
	t.Helper()
	data := []byte("id,v\n1,a\n1,b\n2,c\n")
	opts, e := tabular.CanonicalOptions("dedupe", json.RawMessage(`{"key_columns":["id"],"keep":"first"}`))
	if e != nil {
		t.Fatal(e)
	}
	q := csvwire.Request{Version: 1, Operation: "dedupe", Options: opts, Files: []csvwire.File{{Slot: "file", Bytes: int64(len(data)), SHA256: Hash(data)}}}
	r, _ := memoryRepo()
	j := fixtureJob()
	j.IntentBinding = q.Binding()
	j.Inputs = []Object{{JobID: j.ID, ID: ID(), Slot: "file", Bytes: int64(len(data)), SHA256: Hash(data)}}
	seed(t, r, j)
	a := Artifacts{Repo: r, Inputs: inputStub{}, Gate: Gate{Enabled: true}, Now: func() time.Time { return fixtureTime }}
	if e = a.AcceptUploads(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	j, e = r.Queue(ctx, readJob(t, r, j.ID), ID(), 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	j = startQueued(t, r, j)
	objects := &processingStore{data: map[string][]byte{"file": data}}
	worker := &processingWorker{}
	p := Processor{Repo: r, Objects: objects, Worker: worker, Gate: Gate{Enabled: true}, Now: func() time.Time { return fixtureTime }}
	return p, j, q, objects, worker
}
func TestPrivateProcessorPublishesOnlyAfterCompleteVerifiedTransferAndStop(t *testing.T) {
	p, j, q, s, w := processorFixture(t)
	if e := p.Process(ctx, j.ID, q); e != nil {
		t.Fatal(e)
	}
	got := readJob(t, p.Repo, j.ID)
	if got.Artifact != "RESULT_PREPARED" || got.Financial != "AWAITING_PAYMENT" || !got.WorkerStopped || s.put != 1 || w.stops != 1 || got.Result.LogicalSHA256 != Hash([]byte("id,v\n1,a\n2,c\n")) {
		t.Fatal("unverified publication")
	}
	if e := p.Process(ctx, j.ID, q); e != ErrConflict || w.calls != 1 {
		t.Fatal("transfer replayed", e)
	}
}
func TestPrivateProcessorRejectsIntentCorruptionAndUncertainStop(t *testing.T) {
	for _, scenario := range []string{"intent", "input", "result", "stop"} {
		t.Run(scenario, func(t *testing.T) {
			p, j, q, s, w := processorFixture(t)
			switch scenario {
			case "intent":
				q.Options = json.RawMessage(`{"key_columns":["id"],"keep":"last"}`)
			case "input":
				s.data["file"] = []byte(strings.Repeat("x", int(q.Files[0].Bytes)))
			case "result":
				w.corrupt = true
			case "stop":
				w.stopFail = true
			}
			if e := p.Process(ctx, j.ID, q); e == nil {
				t.Fatal("invalid transfer accepted")
			}
			if s.put != 0 || readJob(t, p.Repo, j.ID).Artifact != "RUNNING" {
				t.Fatal("unverified result stored/published")
			}
			if scenario != "intent" {
				if e := p.Process(ctx, j.ID, q); e != ErrConflict || w.calls > 1 {
					t.Fatal("uncertain transfer replayed", e)
				}
			}
		})
	}
}
