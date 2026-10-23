package csvcloud

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"pdfservice/internal/csvwire"
	"pdfservice/internal/jsonwire"
)

// PrivateRunBackend serves one predeclared synthetic fixture in pre-created
// resources. It cannot create IAM/storage resources, dispatch compute, contact a
// payment provider or mark a real job PAID. The separate bounded controller
// consumes its transactional outbox and owns task/recovery verification.
type PrivateRunBackend struct {
	RunID         string
	Until         int64
	SyntheticOnly bool
	Request       csvwire.Request
	Repo          Repository
	Objects       Storage
	Queue         Queue
	Now           func() time.Time
}

type privateUploadRecord struct {
	Version int64
	State   string
	Upload  Upload
}
type privateDeliveryRecord struct {
	Version                 int64
	Manifest                string
	Used                    int64
	Lease, LastLease, State string
	Until                   int64
}

func (b PrivateRunBackend) now() int64 {
	if b.Now != nil {
		return b.Now().Unix()
	}
	return time.Now().Unix()
}
func (b PrivateRunBackend) valid() bool {
	return b.SyntheticOnly && opaque(b.RunID) && b.Request.Validate() == nil && b.Until > b.now() && b.Until <= b.now()+7200 && b.Repo.Client != nil && b.Repo.Gate.Enabled && b.Repo.Table == "utils-bot-csv-private-"+b.RunID[:16] && b.Objects.Client != nil && b.Objects.Presigner != nil && b.Objects.Gate.Enabled && b.Objects.Bucket == "utils-csv-"+b.Objects.Account+"-"+b.RunID[:24] && b.Queue.Client != nil && b.Queue.Gate.Enabled && b.Queue.Repo.Table == b.Repo.Table && b.Queue.URL == "https://sqs.us-east-2.amazonaws.com/"+b.Objects.Account+"/"+b.Repo.Table
}
func (b PrivateRunBackend) job(ctx context.Context, id string) (*Job, error) {
	if !b.valid() {
		return nil, ErrDisabled
	}
	if id != b.RunID {
		return nil, ErrInvalid
	}
	j, err := b.Repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if j == nil {
		return nil, ErrConflict
	}
	if j.Artifact != "ERASED" && j.IntentBinding != b.Request.Binding() {
		return nil, ErrIntegrity
	}
	return j, nil
}
func (b PrivateRunBackend) read(ctx context.Context, pk string, dst any) (int64, error) {
	row, err := b.Repo.get(ctx, pk)
	if err != nil {
		return 0, err
	}
	if len(row) == 0 {
		return 0, nil
	}
	raw, ok := row["data"].(*d.AttributeValueMemberB)
	if !ok || jsonwire.Decode(raw.Value, dst, MaxMetadata) != nil {
		return 0, ErrIntegrity
	}
	v := parseVersion(avsPrivate(row["version"]))
	if v < 1 {
		return 0, ErrIntegrity
	}
	return v, nil
}
func avsPrivate(value d.AttributeValue) string {
	switch v := value.(type) {
	case *d.AttributeValueMemberS:
		return v.Value
	case *d.AttributeValueMemberN:
		return v.Value
	}
	return ""
}
func (b PrivateRunBackend) write(ctx context.Context, pk string, old int64, value any, j *Job) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxMetadata {
		return ErrInvalid
	}
	put := &d.Put{TableName: aws.String(b.Repo.Table), Item: map[string]d.AttributeValue{"pk": str(pk), "version": num(old + 1), "data": &d.AttributeValueMemberB{Value: raw}}, ConditionExpression: aws.String("attribute_not_exists(pk)")}
	if old > 0 {
		put.ConditionExpression = aws.String("#v = :v")
		put.ExpressionAttributeNames = map[string]string{"#v": "version"}
		put.ExpressionAttributeValues = map[string]d.AttributeValue{":v": num(old)}
	}
	items := []d.TransactWriteItem{{Put: put}}
	if j != nil {
		items = append(items, d.TransactWriteItem{ConditionCheck: &d.ConditionCheck{TableName: aws.String(b.Repo.Table), Key: key("JOB/" + j.ID), ConditionExpression: aws.String("#v = :v"), ExpressionAttributeNames: map[string]string{"#v": "version"}, ExpressionAttributeValues: map[string]d.AttributeValue{":v": num(j.Version)}}})
	}
	return b.Repo.txn(ctx, items)
}
func (b PrivateRunBackend) upload(ctx context.Context, o Object) (privateUploadRecord, error) {
	var r privateUploadRecord
	version, err := b.read(ctx, "API_UPLOAD/"+o.ID, &r)
	if err != nil {
		return r, err
	}
	if version == 0 || r.Version != version || r.Upload.Object.JobID != b.RunID || r.Upload.Object.ID != o.ID || r.Upload.Object.Slot != o.Slot || r.Upload.Object.Bytes != o.Bytes || r.Upload.Object.SHA256 != o.SHA256 || !r.Upload.valid() {
		return r, ErrIntegrity
	}
	return r, nil
}
func (b PrivateRunBackend) Begin(ctx context.Context, q csvwire.Request) (PrivateAdmission, error) {
	var reply PrivateAdmission
	if !b.valid() || q.Validate() != nil || q.Binding() != b.Request.Binding() {
		return reply, ErrInvalid
	}
	j, err := b.Repo.Get(ctx, b.RunID)
	if err != nil {
		return reply, err
	}
	if j == nil {
		fresh := Job{ID: b.RunID, IntentBinding: q.Binding(), Owner: "0x1111111111111111111111111111111111111111", AdmissionNonceHash: Hash([]byte("private-admission/" + b.RunID)), IdempotencyHash: Hash([]byte("private-idempotency/" + b.RunID)), RecoveryVerifier: ID(), CapabilityVerifier: ID(), Version: 1, Artifact: "UPLOAD_INCOMPLETE", Financial: "UNPAID", UploadUntil: min(b.Until, b.now()+300)}
		for _, f := range q.Files {
			fresh.Inputs = append(fresh.Inputs, Object{JobID: fresh.ID, ID: ID(), Slot: f.Slot, Bytes: f.Bytes, SHA256: f.SHA256})
		}
		if err = b.Repo.Create(ctx, fresh, 1); err != nil {
			return reply, err
		}
		// All side-effecting calls below are preceded by durable intent. Lost
		// responses retain the original object/upload identity; never create again.
		for _, o := range fresh.Inputs {
			r := privateUploadRecord{Version: 1, State: "CREATING", Upload: Upload{Object: o, Parts: []Part{{Number: 1, Bytes: o.Bytes, SHA256: o.SHA256}}, Expires: fresh.UploadUntil}}
			if err = b.write(ctx, "API_UPLOAD/"+o.ID, 0, r, &fresh); err != nil {
				return reply, err
			}
			u, e := b.Objects.Begin(ctx, r.Upload)
			if e != nil {
				return reply, e
			}
			r.Version++
			r.State = "OPEN"
			r.Upload = u
			if err = b.write(ctx, "API_UPLOAD/"+o.ID, 1, r, &fresh); err != nil {
				return reply, err
			}
		}
		j = &fresh
	}
	if j.IntentBinding != q.Binding() || j.Artifact != "UPLOAD_INCOMPLETE" || j.Financial != "UNPAID" || j.UploadUntil <= b.now() {
		return reply, ErrConflict
	}
	reply = PrivateAdmission{JobID: j.ID, Expires: j.UploadUntil, PaymentMode: "synthetic-no-funds"}
	for _, o := range j.Inputs {
		r, e := b.upload(ctx, o)
		if e != nil {
			return PrivateAdmission{}, e
		}
		if r.State != "OPEN" {
			return PrivateAdmission{}, ErrUnknown
		}
		grant, e := b.Objects.Grant(ctx, r.Upload, 1, time.Unix(b.now(), 0))
		if e != nil {
			return PrivateAdmission{}, e
		}
		reply.Parts = append(reply.Parts, PrivatePart{Slot: o.Slot, Number: 1, URL: grant.URL, Headers: grant.Headers})
	}
	return reply, nil
}

// Complete only durably signals the bounded controller. Full-file hashing,
// multipart completion and queue publication run outside the live PDF API.
func (b PrivateRunBackend) Complete(ctx context.Context, id string) error {
	j, err := b.job(ctx, id)
	if err != nil {
		return err
	}
	switch j.Artifact {
	case "UPLOAD_VERIFIED", "QUEUED", "DISPATCH_RESERVED", "RUNNING", "RESULT_PREPARED":
		return nil
	case "UPLOAD_INCOMPLETE":
	default:
		return ErrConflict
	}
	if j.Financial != "UNPAID" || j.UploadUntil <= b.now() {
		return ErrConflict
	}
	var old struct {
		Version int64
		Binding string
	}
	version, err := b.read(ctx, "API_COMPLETE/"+id, &old)
	if err != nil {
		return err
	}
	if version > 0 {
		if version != old.Version || old.Binding != j.IntentBinding {
			return ErrIntegrity
		}
		return nil
	}
	next := struct {
		Version int64
		Binding string
	}{1, j.IntentBinding}
	if err = b.write(ctx, "API_COMPLETE/"+id, 0, next, j); err != nil {
		var observed struct {
			Version int64
			Binding string
		}
		version, e := b.read(ctx, "API_COMPLETE/"+id, &observed)
		if e == nil && version == 1 && observed.Version == 1 && observed.Binding == j.IntentBinding {
			return nil
		}
		return err
	}
	return nil
}

// VerifyAndQueue belongs to the separate bounded controller, never an HTTP
// route. That identity can read input bytes; the API identity cannot.
func (b PrivateRunBackend) VerifyAndQueue(ctx context.Context, id string) error {
	j, err := b.job(ctx, id)
	if err != nil {
		return err
	}
	var signal struct {
		Version int64
		Binding string
	}
	v, e := b.read(ctx, "API_COMPLETE/"+id, &signal)
	if e != nil {
		return e
	}
	if v != 1 || signal.Version != 1 || signal.Binding != j.IntentBinding {
		return ErrConflict
	}
	if j.Artifact == "QUEUED" {
		row, e := b.Repo.get(ctx, "OUTBOX/"+id)
		if e != nil {
			return e
		}
		if avsPrivate(row["state"]) == "SENT" {
			return nil
		}
		if avsPrivate(row["state"]) == "PENDING" {
			return b.Queue.Publish(ctx, id)
		}
		// SENDING/SEND_UNKNOWN are reconciliation states, never another send.
		return ErrUnknown
	}
	if j.Artifact == "UPLOAD_VERIFIED" && j.Financial == "UNPAID" {
		return b.queue(ctx, *j)
	}
	if j.Artifact != "UPLOAD_INCOMPLETE" || j.Financial != "UNPAID" || j.UploadUntil <= b.now() {
		return ErrConflict
	}
	next := copyJob(*j)
	for i, o := range j.Inputs {
		r, e := b.upload(ctx, o)
		if e != nil {
			return e
		}
		switch r.State {
		case "OPEN":
			pending := r
			pending.Version++
			pending.State = "COMPLETING"
			if e = b.write(ctx, "API_UPLOAD/"+o.ID, r.Version, pending, j); e != nil {
				return e
			}
			r = pending
			completed, e := b.Objects.Complete(ctx, r.Upload)
			if e != nil {
				return e
			}
			r.Upload.Object = completed
		case "COMPLETING":
			// Reconcile only the original immutable key after an ambiguous complete.
			completed, e := b.Objects.VerifyInput(ctx, r.Upload.Object)
			if e != nil {
				return e
			}
			r.Upload.Object = completed
		case "COMPLETE":
			next.Inputs[i] = r.Upload.Object
			continue
		default:
			return ErrUnknown
		}
		oldVersion := r.Version
		r.Version++
		r.State = "COMPLETE"
		if e = b.write(ctx, "API_UPLOAD/"+o.ID, oldVersion, r, j); e != nil {
			return e
		}
		next.Inputs[i] = r.Upload.Object
	}
	next.Version++
	next.Artifact = "UPLOAD_VERIFIED"
	if err = b.Repo.advanceVerified(ctx, *j, next); err != nil {
		return err
	}
	return b.queue(ctx, next)
}
func (b PrivateRunBackend) queue(ctx context.Context, j Job) error {
	token := Hash([]byte("private-dispatch/" + b.RunID))
	queued, err := b.Repo.Queue(ctx, j, token, 10_000_000, 10_000_000)
	if err != nil {
		observed, e := b.Repo.Get(ctx, j.ID)
		if e != nil || observed == nil || observed.Artifact != "QUEUED" || observed.Dispatch == nil || observed.Dispatch.Token != token {
			return err
		}
		queued = *observed
	}
	return b.Queue.Publish(ctx, queued.ID)
}
func (b PrivateRunBackend) Status(ctx context.Context, id string) (PrivateStatus, error) {
	j, err := b.job(ctx, id)
	if err != nil {
		return PrivateStatus{}, err
	}
	status := PrivateStatus{JobID: j.ID, State: j.Artifact, Financial: j.Financial, PaymentMode: "synthetic-no-funds"}
	if j.Result != nil {
		status.Rows = j.Result.Rows
		status.EncodedBytes = j.Result.Object.Bytes
		status.LogicalBytes = j.Result.LogicalBytes
	}
	return status, nil
}
func privateManifest(m *Manifest) string { raw, _ := json.Marshal(m); return Hash(raw) }
func (b PrivateRunBackend) result(ctx context.Context, id string) (*Job, error) {
	j, err := b.job(ctx, id)
	if err != nil {
		return nil, err
	}
	if j.Artifact != "RESULT_PREPARED" || j.Financial != "AWAITING_PAYMENT" || j.Settlement != nil || j.Result == nil || !j.Result.Valid() || j.ResultUntil <= b.now() {
		return nil, ErrConflict
	}
	return j, nil
}
func (b PrivateRunBackend) delivery(ctx context.Context) (privateDeliveryRecord, error) {
	var r privateDeliveryRecord
	version, err := b.read(ctx, "API_DELIVERY/"+b.RunID, &r)
	if err != nil {
		return r, err
	}
	if version == 0 {
		return r, nil
	}
	if r.Version != version || !opaque(r.Manifest) || r.Used < 0 || r.Until < 0 || r.Lease != "" && !opaque(r.Lease) || r.LastLease != "" && !opaque(r.LastLease) {
		return r, ErrIntegrity
	}
	switch r.State {
	case "SIMULATED", "DOWNLOADING", "COMPLETE", "INCOMPLETE":
	default:
		return r, ErrIntegrity
	}
	if (r.State == "DOWNLOADING") != (r.Lease != "") {
		return r, ErrIntegrity
	}
	return r, nil
}
func (b PrivateRunBackend) SimulatePayment(ctx context.Context, id string) error {
	j, err := b.result(ctx, id)
	if err != nil {
		return err
	}
	r, err := b.delivery(ctx)
	if err != nil {
		return err
	}
	binding := privateManifest(j.Result)
	if r.Version > 0 {
		if r.Manifest != binding {
			return ErrIntegrity
		}
		return nil
	}
	return b.write(ctx, "API_DELIVERY/"+id, 0, privateDeliveryRecord{Version: 1, Manifest: binding, State: "SIMULATED"}, j)
}
func (b PrivateRunBackend) endDelivery(ctx context.Context, lease, binding string, complete bool) error {
	r, err := b.delivery(ctx)
	if err != nil {
		return err
	}
	if r.Manifest != binding {
		return ErrIntegrity
	}
	if r.Lease == "" && r.LastLease == lease {
		// An ambiguous Finish that actually committed must not be undone by Abort.
		if r.State == "COMPLETE" || !complete && r.State == "INCOMPLETE" {
			return nil
		}
		return ErrConflict
	}
	if r.Lease != lease || r.State != "DOWNLOADING" {
		return ErrConflict
	}
	old := r.Version
	r.Version++
	r.Lease = ""
	r.LastLease = lease
	r.Until = 0
	r.State = "INCOMPLETE"
	if complete {
		r.State = "COMPLETE"
	}
	if err = b.write(ctx, "API_DELIVERY/"+b.RunID, old, r, nil); err != nil {
		observed, e := b.delivery(ctx)
		if e == nil && observed.Version == r.Version && observed.LastLease == lease && observed.State == r.State {
			return nil
		}
		// The original DOWNLOADING/lease/deadline remains durable on an unknown
		// response; do not refund bytes or assert completion from a callback alone.
		return err
	}
	return nil
}
func (b PrivateRunBackend) Download(ctx context.Context, id string) (PrivateDownload, error) {
	var reply PrivateDownload
	j, err := b.result(ctx, id)
	if err != nil {
		return reply, err
	}
	r, err := b.delivery(ctx)
	if err != nil {
		return reply, err
	}
	if r.Version == 0 {
		return reply, ErrPrivateUnpaid
	}
	binding := privateManifest(j.Result)
	if r.Manifest != binding {
		return reply, ErrIntegrity
	}
	if r.Lease != "" || r.Used > 3*j.Result.Object.Bytes-j.Result.Object.Bytes {
		return reply, ErrConflict
	}
	lease := ID()
	// Create both release/completion paths before the durable reservation.
	reply = PrivateDownload{Bytes: j.Result.Object.Bytes, SHA256: j.Result.Object.SHA256, Finish: func(c context.Context) error { return b.endDelivery(c, lease, binding, true) }, Abort: func(c context.Context) error { return b.endDelivery(c, lease, binding, false) }}
	pending := r
	pending.Version++
	pending.Used += j.Result.Object.Bytes
	pending.Lease = lease
	pending.LastLease = ""
	pending.State = "DOWNLOADING"
	pending.Until = min(j.ResultUntil, b.now()+90)
	if err = b.write(ctx, "API_DELIVERY/"+id, r.Version, pending, j); err != nil {
		observed, e := b.delivery(ctx)
		if e != nil || observed.Version != pending.Version || observed.Lease != lease {
			return PrivateDownload{}, err
		}
	}
	handedOff := false
	defer func() {
		if !handedOff {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = reply.Abort(cleanup)
		}
	}()
	read, cancel := context.WithDeadline(ctx, time.Unix(pending.Until, 0))
	out, err := b.Objects.Client.GetObject(read, &s3.GetObjectInput{Bucket: aws.String(b.Objects.Bucket), Key: aws.String(j.Result.Object.key(true)), ExpectedBucketOwner: aws.String(b.Objects.Account), IfMatch: aws.String(j.Result.Object.ETag)}, noS3Retry)
	if err != nil {
		cancel()
		return PrivateDownload{}, ErrUnknown
	}
	if out.Body == nil || aws.ToString(out.ETag) != j.Result.Object.ETag || aws.ToInt64(out.ContentLength) != reply.Bytes || out.VersionId != nil || len(out.Metadata) != 0 || out.ServerSideEncryption != "AES256" {
		if out.Body != nil {
			out.Body.Close()
		}
		cancel()
		return PrivateDownload{}, ErrIntegrity
	}
	reply.Body = &limitedBody{Reader: io.LimitReader(out.Body, reply.Bytes), Closer: out.Body, cancel: cancel}
	handedOff = true
	return reply, nil
}
func (b PrivateRunBackend) Cancel(ctx context.Context, id string) error {
	j, err := b.job(ctx, id)
	if err != nil {
		return err
	}
	if j.Artifact == "DELETING" || j.Artifact == "ERASED" {
		return nil
	}
	if j.Settlement != nil || j.Financial != "UNPAID" && j.Financial != "AWAITING_PAYMENT" {
		return ErrConflict
	}
	fence, err := privateDeliveryFence(ctx, b.Repo, id)
	if err != nil {
		return err
	}
	next := copyJob(*j)
	next.Version++
	next.Artifact = "DELETING"
	if !validReplacement(*j, next) {
		return ErrInvalid
	}
	return b.Repo.txn(ctx, []d.TransactWriteItem{b.Repo.versioned(*j, next), {ConditionCheck: fence}})
}

// A fixed fixture set admits no arbitrary customer content. All methods select
// the pre-created run before making any AWS call, including guessed job IDs.
type PrivateBackendSet map[string]*PrivateRunBackend

func (s PrivateBackendSet) Begin(ctx context.Context, q csvwire.Request) (PrivateAdmission, error) {
	var match *PrivateRunBackend
	for _, b := range s {
		if b != nil && b.Request.Binding() == q.Binding() {
			if match != nil {
				return PrivateAdmission{}, ErrInvalid
			}
			match = b
		}
	}
	if match == nil {
		return PrivateAdmission{}, ErrInvalid
	}
	return match.Begin(ctx, q)
}
func (s PrivateBackendSet) selectRun(id string) (*PrivateRunBackend, error) {
	b := s[id]
	if !opaque(id) || b == nil || b.RunID != id {
		return nil, ErrInvalid
	}
	return b, nil
}
func (s PrivateBackendSet) Complete(c context.Context, id string) error {
	b, e := s.selectRun(id)
	if e != nil {
		return e
	}
	return b.Complete(c, id)
}
func (s PrivateBackendSet) Status(c context.Context, id string) (PrivateStatus, error) {
	b, e := s.selectRun(id)
	if e != nil {
		return PrivateStatus{}, e
	}
	return b.Status(c, id)
}
func (s PrivateBackendSet) SimulatePayment(c context.Context, id string) error {
	b, e := s.selectRun(id)
	if e != nil {
		return e
	}
	return b.SimulatePayment(c, id)
}
func (s PrivateBackendSet) Download(c context.Context, id string) (PrivateDownload, error) {
	b, e := s.selectRun(id)
	if e != nil {
		return PrivateDownload{}, e
	}
	return b.Download(c, id)
}
func (s PrivateBackendSet) Cancel(c context.Context, id string) error {
	b, e := s.selectRun(id)
	if e != nil {
		return e
	}
	return b.Cancel(c, id)
}

// This CAS closes the race between retiring an unpaid synthetic result and
// acquiring its separate simulated download lease. Unknown evidence holds it.
func privateDeliveryFence(ctx context.Context, repo Repository, id string) (*d.ConditionCheck, error) {
	b := PrivateRunBackend{RunID: id, Repo: repo}
	record, err := b.delivery(ctx)
	if err != nil {
		return nil, err
	}
	if record.Lease != "" {
		return nil, ErrConflict
	}
	check := &d.ConditionCheck{TableName: aws.String(repo.Table), Key: key("API_DELIVERY/" + id), ConditionExpression: aws.String("attribute_not_exists(pk)")}
	if record.Version > 0 {
		check.ConditionExpression = aws.String("#v = :v")
		check.ExpressionAttributeNames = map[string]string{"#v": "version"}
		check.ExpressionAttributeValues = map[string]d.AttributeValue{":v": num(record.Version)}
	}
	return check, nil
}
