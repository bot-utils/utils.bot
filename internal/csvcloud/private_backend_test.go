package csvcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	tabular "pdfservice/internal/csvtabular"
	"pdfservice/internal/csvwire"
)

type privateBackendFixture struct {
	b                                       *PrivateRunBackend
	db                                      *memoryDynamo
	queue                                   *fakeSQS
	data                                    []byte
	result                                  Manifest
	encoded                                 []byte
	creates, completes, gets                int
	lostCreate, lostComplete, failResultGet bool
}

func newPrivateBackendFixture(t *testing.T) *privateBackendFixture {
	t.Helper()
	f := &privateBackendFixture{data: []byte("id\nhello\n")}
	run := ID()
	repo, db := memoryRepo()
	repo.Table = "utils-bot-csv-private-" + run[:16]
	options, err := tabular.CanonicalOptions("transform", json.RawMessage(`{"column":"id","op":"upper"}`))
	if err != nil {
		t.Fatal(err)
	}
	request := csvwire.Request{Version: 1, Operation: "transform", Options: options, Files: []csvwire.File{{Slot: "file", Bytes: int64(len(f.data)), SHA256: Hash(f.data)}}}
	f.result, f.encoded = manifest(run)
	objects := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == "POST" && req.URL.Query().Has("uploads"):
			f.creates++
			if f.lostCreate {
				return nil, errors.New("synthetic create reply lost")
			}
			return response(200, `<InitiateMultipartUploadResult><UploadId>synthetic-upload</UploadId></InitiateMultipartUploadResult>`, nil), nil
		case req.Method == "GET" && req.URL.Query().Get("uploadId") != "":
			body := `<ListPartsResult><IsTruncated>false</IsTruncated><Part><PartNumber>1</PartNumber><ETag>"part"</ETag><Size>` + strconv.Itoa(len(f.data)) + `</Size><ChecksumSHA256>` + checksum(Hash(f.data)) + `</ChecksumSHA256></Part></ListPartsResult>`
			return response(200, body, nil), nil
		case req.Method == "POST" && req.URL.Query().Get("uploadId") != "":
			f.completes++
			if f.lostComplete {
				return nil, errors.New("synthetic complete reply lost")
			}
			return response(200, `<CompleteMultipartUploadResult><ETag>"input"</ETag></CompleteMultipartUploadResult>`, nil), nil
		case req.Method == "HEAD":
			return response(200, "", http.Header{"Content-Length": {strconv.Itoa(len(f.data))}, "Etag": {`"input"`}, "X-Amz-Server-Side-Encryption": {"AES256"}}), nil
		case req.Method == "GET":
			f.gets++
			if strings.HasPrefix(req.URL.Path, "/results/") {
				if f.failResultGet {
					return nil, errors.New("synthetic result unavailable")
				}
				return response(200, string(f.encoded), headers(f.result)), nil
			}
			return response(200, string(f.data), http.Header{"Content-Length": {strconv.Itoa(len(f.data))}, "Etag": {`"input"`}, "X-Amz-Server-Side-Encryption": {"AES256"}}), nil
		default:
			t.Fatalf("unexpected provider request %s", req.Method)
			return nil, ErrInvalid
		}
	}))
	objects.Bucket = "utils-csv-" + objects.Account + "-" + run[:24]
	queue := &fakeSQS{}
	b := &PrivateRunBackend{RunID: run, Until: fixtureTime.Unix() + 7200, SyntheticOnly: true, Request: request, Repo: repo, Objects: objects, Now: func() time.Time { return fixtureTime }}
	b.Queue = Queue{Client: queue, URL: "https://sqs.us-east-2.amazonaws.com/" + objects.Account + "/" + repo.Table, Repo: repo, Gate: Gate{Enabled: true}}
	f.b = b
	f.db = db
	f.queue = queue
	return f
}
func (f *privateBackendFixture) ready(t *testing.T) {
	t.Helper()
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
	j = transferProof(t, f.b.Repo, j)
	if _, e := f.b.Repo.publishResult(ctx, j, f.result, fixtureTime.Unix()+300); e != nil {
		t.Fatal(e)
	}
}
func TestPrivateAWSBackendPinnedAdmissionAndOneShotQueue(t *testing.T) {
	f := newPrivateBackendFixture(t)
	changed := f.b.Request
	changed.Files = append([]csvwire.File(nil), changed.Files...)
	changed.Files[0].SHA256 = ID()
	if _, err := f.b.Begin(ctx, changed); err != ErrInvalid || f.creates != 0 {
		t.Fatal("unpinned input admitted", err)
	}
	first, err := f.b.Begin(ctx, f.b.Request)
	if err != nil || len(first.Parts) != 1 {
		t.Fatal(err)
	}
	again, err := f.b.Begin(ctx, f.b.Request)
	if err != nil || again.JobID != first.JobID || f.creates != 1 {
		t.Fatal("duplicate MPU created", err)
	}
	if err = f.b.Complete(ctx, first.JobID); err != nil {
		t.Fatal(err)
	}
	if f.completes != 0 || f.queue.calls != 0 {
		t.Fatal("HTTP completion did full-file work")
	}
	if err = f.b.VerifyAndQueue(ctx, first.JobID); err != nil {
		t.Fatal(err)
	}
	if err = f.b.VerifyAndQueue(ctx, first.JobID); err != nil || f.completes != 1 || f.queue.calls != 1 {
		t.Fatal("completion or queue replay", err)
	}
	status, err := f.b.Status(ctx, first.JobID)
	if err != nil || status.State != "QUEUED" || status.Financial != "UNPAID" {
		t.Fatal("job state", err)
	}
}
func TestPrivateAWSBackendNeverRepeatsAmbiguousUploadOrSend(t *testing.T) {
	for _, scenario := range []string{"create", "complete", "send"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPrivateBackendFixture(t)
			if scenario == "create" {
				f.lostCreate = true
				if _, e := f.b.Begin(ctx, f.b.Request); e == nil {
					t.Fatal("unknown create succeeded")
				}
				if _, e := f.b.Begin(ctx, f.b.Request); e == nil || f.creates != 1 {
					t.Fatal("unknown create repeated", e)
				}
				return
			}
			if _, e := f.b.Begin(ctx, f.b.Request); e != nil {
				t.Fatal(e)
			}
			if e := f.b.Complete(ctx, f.b.RunID); e != nil {
				t.Fatal(e)
			}
			if scenario == "complete" {
				f.lostComplete = true
			} else {
				f.queue.lost = true
			}
			if e := f.b.VerifyAndQueue(ctx, f.b.RunID); e == nil {
				t.Fatal("unknown completion/send accepted")
			}
			// An ambiguous completion can only verify the original immutable key.
			// The fake provider now exposes that object; it never receives Complete twice.
			_ = f.b.VerifyAndQueue(ctx, f.b.RunID)
			if f.completes != 1 || scenario == "send" && f.queue.calls != 1 {
				t.Fatal("ambiguous side effect replayed")
			}
		})
	}
}
func TestPrivateAWSBackendSimulatedPaymentKeepsRealLedgerUnpaid(t *testing.T) {
	f := newPrivateBackendFixture(t)
	f.ready(t)
	if _, e := f.b.Download(ctx, f.b.RunID); e != ErrPrivateUnpaid {
		t.Fatal("unpaid result readable", e)
	}
	if e := f.b.SimulatePayment(ctx, f.b.RunID); e != nil {
		t.Fatal(e)
	}
	if e := f.b.SimulatePayment(ctx, f.b.RunID); e != nil {
		t.Fatal(e)
	}
	job := readJob(t, f.b.Repo, f.b.RunID)
	if job.Financial != "AWAITING_PAYMENT" || job.Settlement != nil || job.Artifact != "RESULT_PREPARED" {
		t.Fatal("simulated payment mutated real financial state")
	}
	for attempt := 0; attempt < 3; attempt++ {
		dl, e := f.b.Download(ctx, f.b.RunID)
		if e != nil || dl.Finish == nil || dl.Abort == nil {
			t.Fatal("lease callbacks absent", e)
		}
		if _, e = f.b.Download(ctx, f.b.RunID); e != ErrConflict {
			t.Fatal("concurrent download admitted", e)
		}
		data, e := io.ReadAll(dl.Body)
		_ = dl.Body.Close()
		if e != nil || !bytes.Equal(data, f.encoded) {
			t.Fatal("gzip changed", e)
		}
		if attempt == 0 {
			e = dl.Abort(ctx)
		} else {
			e = dl.Finish(ctx)
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = dl.Abort(ctx); e != nil {
			t.Fatal("release not idempotent", e)
		}
	}
	before := f.gets
	if _, e := f.b.Download(ctx, f.b.RunID); e != ErrConflict || f.gets != before {
		t.Fatal("retry budget exceeded", e)
	}
	record, e := f.b.delivery(ctx)
	if e != nil || record.Used != 3*f.result.Object.Bytes || record.State != "COMPLETE" {
		t.Fatal("byte charges or completion evidence", e)
	}
}
func TestPrivateAWSBackendDownloadFailureAndLostRepliesRetainEvidence(t *testing.T) {
	f := newPrivateBackendFixture(t)
	f.ready(t)
	if e := f.b.SimulatePayment(ctx, f.b.RunID); e != nil {
		t.Fatal(e)
	}
	f.failResultGet = true
	if _, e := f.b.Download(ctx, f.b.RunID); e != ErrUnknown {
		t.Fatal(e)
	}
	record, e := f.b.delivery(ctx)
	if e != nil || record.Lease != "" || record.State != "INCOMPLETE" || record.Used != f.result.Object.Bytes {
		t.Fatal("failed open leaked lease or refunded bytes", e)
	}
	f.failResultGet = false
	f.db.lost = true
	dl, e := f.b.Download(ctx, f.b.RunID)
	if e != nil {
		t.Fatal("lost claim reply was not reconciled", e)
	}
	_ = dl.Body.Close()
	f.db.lost = true
	if e = dl.Finish(ctx); e != nil {
		t.Fatal("lost finish reply was not reconciled", e)
	}
	if e = dl.Abort(ctx); e != nil {
		t.Fatal("abort undid committed finish", e)
	}
	record, e = f.b.delivery(ctx)
	if e != nil || record.State != "COMPLETE" || record.Used != 2*f.result.Object.Bytes {
		t.Fatal("durable finish evidence", e)
	}
}
func TestPrivateAWSBackendRetirementIsAtomicWithDownloadLease(t *testing.T) {
	f := newPrivateBackendFixture(t)
	f.ready(t)
	if e := f.b.SimulatePayment(ctx, f.b.RunID); e != nil {
		t.Fatal(e)
	}
	j := readJob(t, f.b.Repo, f.b.RunID)
	staleFence, e := privateDeliveryFence(ctx, f.b.Repo, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	dl, e := f.b.Download(ctx, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.b.Cancel(ctx, j.ID); e != ErrConflict {
		t.Fatal("cancel ignored active lease", e)
	}
	c := Controller{Config: ControllerConfig{SyntheticOnly: true, JobID: j.ID}, Repo: f.b.Repo}
	if e = c.FinishSynthetic(ctx); e != ErrConflict {
		t.Fatal("controller ignored active lease", e)
	}
	next := copyJob(j)
	next.Version++
	next.Artifact = "DELETING"
	if e = f.b.Repo.txn(ctx, []d.TransactWriteItem{f.b.Repo.versioned(j, next), {ConditionCheck: staleFence}}); e != ErrConflict {
		t.Fatal("stale retirement crossed lease reservation", e)
	}
	_ = dl.Body.Close()
	if e = dl.Abort(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = c.FinishSynthetic(ctx); e != nil {
		t.Fatal("released lease blocked retirement", e)
	}
}
func TestPrivateAWSBackendRejectsOtherRunBeforeProviderCalls(t *testing.T) {
	f := newPrivateBackendFixture(t)
	set := PrivateBackendSet{f.b.RunID: f.b}
	if _, e := set.Status(ctx, ID()); e != ErrInvalid || f.creates != 0 || f.gets != 0 || len(f.db.transactions) != 0 {
		t.Fatal("unconfigured run reached provider", e)
	}
	f.b.SyntheticOnly = false
	if _, e := f.b.Begin(ctx, f.b.Request); e != ErrInvalid || len(f.db.transactions) != 0 {
		t.Fatal("non-synthetic backend admitted", e)
	}
}

func TestPrivateLargeMultipartAdmissionPinsEveryPart(t *testing.T) {
	f := newPrivateBackendFixture(t)
	f.b.Request.Version = 2
	f.b.Request.Files[0].Bytes = 1 << 30
	parts := []Part{}
	for i := 0; i < 16; i++ {
		parts = append(parts, Part{Number: int32(i + 1), Bytes: 64 << 20, SHA256: Hash([]byte(strconv.Itoa(i)))})
	}
	f.b.Parts = map[string][]Part{"file": parts}
	admission, e := f.b.Begin(ctx, f.b.Request)
	if e != nil || len(admission.Parts) != 16 || f.creates != 1 || f.gets != 0 {
		t.Fatal("large metadata admission", e)
	}
	for i, p := range admission.Parts {
		if p.Number != int32(i+1) || http.Header(p.Headers).Get("Content-Length") != "67108864" || http.Header(p.Headers).Get("X-Amz-Checksum-Sha256") != checksum(parts[i].SHA256) {
			t.Fatal("part plan not pinned")
		}
	}
	for _, scenario := range []string{"missing", "total", "number", "hash", "oversized"} {
		copied := append([]Part(nil), parts...)
		switch scenario {
		case "missing":
			copied = copied[:15]
		case "total":
			copied[15].Bytes--
		case "number":
			copied[5].Number = 1
		case "hash":
			copied[3].SHA256 = "bad"
		case "oversized":
			copied[0].Bytes++
			copied[15].Bytes--
		}
		run := PrivateAPIRun{ID: f.b.RunID, Request: f.b.Request, Parts: map[string][]Part{"file": copied}}
		if privatePartPlanValid(run) {
			t.Fatal("invalid part plan admitted", scenario)
		}
	}
}
