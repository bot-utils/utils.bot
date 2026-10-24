package csvcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"io"
	tabular "pdfservice/internal/csvtabular"
	"pdfservice/internal/csvwire"
	"strings"
	"testing"
	"time"
)

type processingStore struct {
	data              map[string][]byte
	openFail, putFail bool
	putHook           func()
	put               int
	manifest          Manifest
	out               []byte
}

func (s *processingStore) OpenInput(_ context.Context, o Object) (io.ReadCloser, error) {
	if s.openFail {
		return nil, ErrUnknown
	}
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
	if s.putHook != nil {
		s.putHook()
	}
	if s.putFail {
		return m, ErrUnknown
	}
	return m, nil
}

type processingWorker struct {
	calls, stops               int
	stopFail, corrupt, runFail bool
}

func (w *processingWorker) Run(_ context.Context, _ Dispatch, q csvwire.Request, in map[string]io.Reader, out io.Writer) (csvwire.Result, error) {
	w.calls++
	if w.runFail {
		return csvwire.Result{}, ErrUnknown
	}
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
			if s.put != 0 || readJob(t, p.Repo, j.ID).Artifact != map[bool]string{true: "RUNNING", false: "PROCESSING_UNKNOWN"}[scenario == "intent"] {
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

func (s *processingStore) EraseAndVerify(context.Context, Job) error {
	s.data = nil
	s.out = nil
	return nil
}

type processingDynamo struct {
	*memoryDynamo
	fail        func(Job) bool
	after, used bool
}

func (s *processingDynamo) TransactWriteItems(c context.Context, q *dynamodb.TransactWriteItemsInput, opts ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	for _, item := range q.TransactItems {
		if item.Put != nil {
			if b, ok := item.Put.Item["data"].(*d.AttributeValueMemberB); ok {
				var j Job
				_ = json.Unmarshal(b.Value, &j)
				if !s.used && s.fail(j) {
					s.used = true
					if !s.after {
						return nil, ErrUnknown
					}
					s.memoryDynamo.lost = true
				}
			}
		}
	}
	return s.memoryDynamo.TransactWriteItems(c, q, opts...)
}
func TestProcessingFailuresRecoverWithoutRedispatchChargeOrOrphan(t *testing.T) {
	for _, stage := range []string{"input_open", "worker", "stop", "put_lost", "claim_lost", "stopped_lost", "publish_failed", "publish_lost", "crash_running"} {
		t.Run(stage, func(t *testing.T) {
			p, j, q, s, w := processorFixture(t)
			memory := p.Repo.Client.(*memoryDynamo)
			f := &fenceStub{}
			p.RecoveryFence = f
			p.Eraser = s
			switch stage {
			case "input_open":
				s.openFail = true
			case "worker":
				w.runFail = true
			case "stop":
				w.stopFail = true
			case "put_lost":
				s.putFail = true
			case "claim_lost", "stopped_lost", "publish_failed", "publish_lost":
				p.Repo.Client = &processingDynamo{memoryDynamo: memory, after: stage != "publish_failed", fail: func(v Job) bool {
					switch stage {
					case "claim_lost":
						return v.Artifact == "RUNNING" && v.TransferStarted
					case "stopped_lost":
						return v.Artifact == "RUNNING" && v.WorkerStopped
					default:
						return v.Artifact == "RESULT_PREPARED"
					}
				}}
			}
			if stage == "crash_running" {
				if _, e := p.Repo.claimTransfer(ctx, j, fixtureTime.Add(2*time.Minute).Unix()); e != nil {
					t.Fatal(e)
				}
			} else if p.Process(ctx, j.ID, q) == nil {
				t.Fatal("injected failure accepted")
			}
			got := readJob(t, p.Repo, j.ID)
			if stage == "publish_lost" {
				if got.Artifact != "RESULT_PREPARED" || got.Financial != "AWAITING_PAYMENT" || len(s.out) == 0 {
					t.Fatal("lost successful publish was destroyed")
				}
				p.Now = func() time.Time { return fixtureTime.Add(3 * time.Minute) }
				if p.Recover(ctx, j.ID) != ErrConflict {
					t.Fatal("payment-eligible result erroneously erased")
				}
				return
			}
			if !got.TransferStarted || got.TransferUntil != fixtureTime.Add(2*time.Minute).Unix() || got.Financial != "UNPAID" {
				t.Fatal("missing durable non-replayable deadline")
			}
			if p.Recover(ctx, j.ID) != ErrConflict || f.calls != 0 {
				t.Fatal("live transfer reaped before deadline")
			}
			beforeCalls := w.calls
			p.Now = func() time.Time { return fixtureTime.Add(3 * time.Minute) }
			w.stopFail = false
			f.err = ErrCleanup
			if p.Recover(ctx, j.ID) != ErrCleanup || avs(memory.rows["CAPACITY"]["used"]) != "1" {
				t.Fatal("capacity released without writer fence")
			}
			f.err = nil
			if e := p.Recover(ctx, j.ID); e != nil {
				t.Fatal("failure not recoverable", e)
			}
			final := readJob(t, p.Repo, j.ID)
			if final.Artifact != "ERASED" || final.Financial != "UNPAID" || s.out != nil || s.data != nil || avs(memory.rows["CAPACITY"]["used"]) != "0" || w.calls != beforeCalls {
				t.Fatal("replayed work, orphan result or capacity leak")
			}
			if p.Process(ctx, j.ID, q) != ErrConflict || p.Recover(ctx, j.ID) != nil || avs(memory.rows["CAPACITY"]["used"]) != "0" {
				t.Fatal("replay/double release")
			}
		})
	}
}
func TestRecoveryCASPreventsLateResultPublication(t *testing.T) {
	p, j, q, s, w := processorFixture(t)
	memory := p.Repo.Client.(*memoryDynamo)
	p.RecoveryFence = &fenceStub{}
	p.Eraser = s
	s.putHook = func() {
		p.Now = func() time.Time { return fixtureTime.Add(3 * time.Minute) }
		if e := p.Recover(ctx, j.ID); e != nil {
			t.Fatal(e)
		}
	}
	if p.Process(ctx, j.ID, q) == nil || readJob(t, p.Repo, j.ID).Artifact != "ERASED" || w.calls != 1 || avs(memory.rows["CAPACITY"]["used"]) != "0" {
		t.Fatal("late publication raced past cleanup")
	}
}
func TestRecoveryEraseUncertaintyKeepsCapacityUntilIndependentAbsence(t *testing.T) {
	p, j, q, _, _ := processorFixture(t)
	p.Worker.(*processingWorker).runFail = true
	_ = p.Process(ctx, j.ID, q)
	p.Now = func() time.Time { return fixtureTime.Add(3 * time.Minute) }
	eraser := &eraseStub{err: ErrCleanup}
	p.Eraser = eraser
	p.RecoveryFence = &fenceStub{}
	if p.Recover(ctx, j.ID) != ErrCleanup || readJob(t, p.Repo, j.ID).Artifact != "DELETING" {
		t.Fatal("uncertain absence was terminal")
	}
	memory := p.Repo.Client.(*memoryDynamo)
	if avs(memory.rows["CAPACITY"]["used"]) != "1" {
		t.Fatal("capacity released early")
	}
	eraser.err = nil
	if p.Recover(ctx, j.ID) != nil || readJob(t, p.Repo, j.ID).Artifact != "ERASED" {
		t.Fatal("cleanup not recoverable")
	}
}
