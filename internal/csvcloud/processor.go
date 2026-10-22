package csvcloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"pdfservice/internal/csvwire"
)

// WorkerSession exposes only the job's bytes/options over a private connection.
// Its implementation must pin the original ECS task endpoint and per-run peer.
type WorkerSession interface {
	Run(context.Context, Dispatch, csvwire.Request, map[string]io.Reader, io.Writer) (csvwire.Result, error)
	StopAndVerify(context.Context, Dispatch) error
}
type MTLSWorker struct {
	Connect func(context.Context, Dispatch) (*tls.Conn, error)
	Stopped func(context.Context, Dispatch) error
}

func (w MTLSWorker) Run(ctx context.Context, d Dispatch, q csvwire.Request, in map[string]io.Reader, out io.Writer) (csvwire.Result, error) {
	if w.Connect == nil {
		return csvwire.Result{}, ErrInvalid
	}
	c, e := w.Connect(ctx, d)
	if e != nil {
		return csvwire.Result{}, ErrUnknown
	}
	return csvwire.Exchange(ctx, c, q, in, out)
}
func (w MTLSWorker) StopAndVerify(ctx context.Context, d Dispatch) error {
	if w.Stopped == nil {
		return ErrCleanup
	}
	return w.Stopped(ctx, d)
}

type ProcessingObjects interface {
	OpenInput(context.Context, Object) (io.ReadCloser, error)
	PutResult(context.Context, Manifest, io.Reader) (Manifest, error)
}
type Processor struct {
	Repo          Repository
	Objects       ProcessingObjects
	Worker        WorkerSession
	RecoveryFence WriterFence
	Eraser        Eraser
	Gate          Gate
	Now           func() time.Time
}

// Process is a private broker operation, not a public endpoint. A conditional
// claim permits one transfer attempt; uncertain sessions are never replayed.
// This v1 uses the strict in-memory 8 MiB engine, not the large spill worker.
func (p Processor) Process(ctx context.Context, id string, q csvwire.Request) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if !p.Gate.Enabled {
		return ErrDisabled
	}
	if p.Worker == nil || p.Objects == nil || q.Validate() != nil {
		return ErrInvalid
	}
	j, e := p.Repo.Get(ctx, id)
	if e != nil || j == nil {
		return ErrConflict
	}
	if j.Artifact != "RUNNING" || j.Dispatch == nil || j.Financial != "UNPAID" || j.IntentBinding != q.Binding() || len(j.Inputs) != len(q.Files) {
		return ErrConflict
	}
	for i, f := range q.Files {
		o := j.Inputs[i]
		if f.Slot != o.Slot || f.Bytes != o.Bytes || f.SHA256 != o.SHA256 {
			return ErrInvalid
		}
	}
	current, e := p.Repo.claimTransfer(ctx, *j, p.now().Add(2*time.Minute).Unix())
	if e != nil {
		return e
	}
	stopped := false
	defer func() {
		if err != nil {
			recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = p.noteFailure(recovery, id, current.Dispatch.Token)
			cancel()
		}
		if !stopped {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = p.Worker.StopAndVerify(cleanup, *current.Dispatch)
		}
	}()
	inputs := map[string]io.Reader{}
	var opened []io.ReadCloser
	defer func() {
		for _, f := range opened {
			f.Close()
		}
	}()
	for _, o := range current.Inputs {
		f, e := p.Objects.OpenInput(ctx, o)
		if e != nil {
			return e
		}
		opened = append(opened, f)
		inputs[o.Slot] = f
	}
	var candidate limitedCandidate
	m, e := p.Worker.Run(ctx, *current.Dispatch, q, inputs, &candidate)
	if e != nil {
		return ErrUnknown
	}
	if csvwire.VerifyResult(m, candidate.Bytes()) != nil {
		return ErrIntegrity
	}
	if e = p.Worker.StopAndVerify(ctx, *current.Dispatch); e != nil {
		return ErrCleanup
	}
	stopped = true
	current, e = p.Repo.transferStopped(ctx, current)
	if e != nil {
		return e
	}
	if ctx.Err() != nil || p.now().Unix() >= current.TransferUntil {
		return ErrUnknown
	}
	manifest := Manifest{Object: Object{JobID: id, ID: ID(), Slot: "result", Bytes: m.EncodedBytes, SHA256: m.EncodedSHA256}, LogicalBytes: m.LogicalBytes, LogicalSHA256: m.LogicalSHA256, Rows: int64(m.Rows)}
	verified, e := p.Objects.PutResult(ctx, manifest, bytes.NewReader(candidate.Bytes()))
	if e != nil {
		return e
	}
	now := p.now()
	if ctx.Err() != nil || now.Unix() >= current.TransferUntil {
		return ErrUnknown
	}
	_, e = p.Repo.publishResult(ctx, current, verified, now.Add(30*time.Minute).Unix())
	return e
}
func (r Repository) claimTransfer(ctx context.Context, old Job, until int64) (Job, error) {
	if !old.valid() || old.Artifact != "RUNNING" || old.TransferStarted || until <= 0 {
		return old, ErrConflict
	}
	n := copyJob(old)
	n.Version++
	n.TransferStarted = true
	n.TransferUntil = until
	return n, r.advanceVerified(ctx, old, n)
}
func (r Repository) transferStopped(ctx context.Context, old Job) (Job, error) {
	if !old.valid() || old.Artifact != "RUNNING" || !old.TransferStarted || old.WorkerStopped {
		return old, ErrConflict
	}
	n := copyJob(old)
	n.Version++
	n.WorkerStopped = true
	return n, r.advanceVerified(ctx, old, n)
}

// OpenInput is internal transfer access, never a customer download grant.
func (s Storage) OpenInput(ctx context.Context, o Object) (io.ReadCloser, error) {
	if !s.Gate.Enabled {
		return nil, ErrDisabled
	}
	if !o.valid() || o.Slot == "result" || o.ETag == "" {
		return nil, ErrInvalid
	}
	v, e := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(o.key(false)), ExpectedBucketOwner: aws.String(s.Account), IfMatch: aws.String(o.ETag)}, noS3Retry)
	if e != nil {
		return nil, ErrUnknown
	}
	if v.VersionId != nil || len(v.Metadata) != 0 || aws.ToString(v.ETag) != o.ETag || aws.ToInt64(v.ContentLength) != o.Bytes || v.ServerSideEncryption != st.ServerSideEncryptionAes256 {
		v.Body.Close()
		return nil, ErrIntegrity
	}
	return v.Body, nil
}

type limitedCandidate struct{ buffer bytes.Buffer }

func (b *limitedCandidate) Write(p []byte) (int, error) {
	if len(p) > csvwire.MaxOutput-b.buffer.Len() {
		return 0, ErrIntegrity
	}
	return b.buffer.Write(p)
}

func (b *limitedCandidate) Bytes() []byte { return b.buffer.Bytes() }

func (p Processor) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// noteFailure is best-effort; a process crash or lost CAS still leaves the
// durable TransferUntil reservation, which Recover can reconcile after expiry.
func (p Processor) noteFailure(ctx context.Context, id, token string) error {
	j, e := p.Repo.Get(ctx, id)
	if e != nil || j == nil {
		return ErrUnknown
	}
	if j.Artifact != "RUNNING" || !j.TransferStarted || j.Dispatch == nil || j.Dispatch.Token != token {
		return nil
	}
	_, e = p.Repo.processingUnknown(ctx, *j)
	return e
}
func (r Repository) processingUnknown(ctx context.Context, old Job) (Job, error) {
	if old.Artifact != "RUNNING" || !old.TransferStarted || old.Dispatch == nil {
		return old, ErrConflict
	}
	n := copyJob(old)
	n.Version++
	n.Artifact = "PROCESSING_UNKNOWN"
	n.Dispatch.State = "TRANSFER_UNKNOWN"
	return n, r.advanceVerified(ctx, old, n)
}

// Recover is a bounded controller/reaper operation. It never reruns processing,
// dispatches, quotes or settles. Invoke for expired RUNNING claims as well as
// PROCESSING_UNKNOWN/DELETING rows, including a lost claim transaction reply.
// The external reaper must schedule from durable state, not process callbacks.
func (p Processor) Recover(ctx context.Context, id string) error {
	if !p.Gate.Enabled {
		return ErrDisabled
	}
	if p.Worker == nil || p.RecoveryFence == nil || p.Eraser == nil {
		return ErrCleanup
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	j, e := p.Repo.Get(ctx, id)
	if e != nil || j == nil {
		return ErrUnknown
	}
	if j.Artifact == "ERASED" {
		return nil
	}
	if !j.TransferStarted || j.Dispatch == nil || j.Financial != "UNPAID" || p.now().Unix() < j.TransferUntil {
		return ErrConflict
	}
	if j.Artifact == "RUNNING" {
		n, e := p.Repo.processingUnknown(ctx, *j)
		if e != nil {
			return e
		}
		j = &n
	}
	if j.Artifact != "PROCESSING_UNKNOWN" && j.Artifact != "DELETING" {
		return ErrConflict
	}
	if p.Worker.StopAndVerify(ctx, *j.Dispatch) != nil {
		return ErrCleanup
	}
	// This fence additionally covers broker S3 writes already in flight and all
	// upload capabilities. A timeout alone is never proof of stopped writers.
	if p.RecoveryFence.VerifyStopped(ctx, *j) != nil {
		return ErrCleanup
	}
	if j.Artifact != "DELETING" {
		n := copyJob(*j)
		n.Version++
		n.Artifact = "DELETING"
		n.WorkerStopped = true
		if e = p.Repo.advanceVerified(ctx, *j, n); e != nil {
			return e
		}
	}
	cleanup := Cleanup{Repo: p.Repo, Writers: p.RecoveryFence, Objects: p.Eraser, Gate: p.Gate}
	return cleanup.Complete(ctx, id)
}
