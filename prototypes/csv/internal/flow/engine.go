package flow

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"utils.bot/csvprototype/internal/api"
	"utils.bot/csvprototype/internal/tabular"
)

type Engine struct {
	Logger   *slog.Logger
	Store    *Store
	Provider Provider
	Work     api.Worker
	Now      func() time.Time
	mu       sync.Mutex
	cancel   map[string]context.CancelFunc
}

func New(store *Store, provider Provider, work api.Worker) (*Engine, error) {
	e := &Engine{Store: store, Provider: provider, Work: work, Now: time.Now, cancel: map[string]context.CancelFunc{}}
	err := store.tx(true, func(d *database) error {
		for _, j := range d.Jobs {
			if j.Token != "" {
				d.Quarantine = true
				j.Quarantined = true
				j.Code = "cleanup_uncertain"
				j.Cancel = true
			}
			if j.Financial == "SETTLEMENT_PENDING" {
				j.Financial = "PAYMENT_UNKNOWN"
				j.UnknownAt = j.Reservation.Started
				j.Artifact = "QUARANTINED"
			}
			// The exclusive process lock proves previous local broker streams terminated.
			j.ActiveDownload = ""
		}
		return nil
	})
	return e, err
}
func (e *Engine) now() int64 { return e.Now().Unix() }
func canonical(i Intent) (Intent, string, error) {
	if i.Delivery != "gzip" {
		return i, "", fail(400, "gzip_required")
	}
	opts, err := tabular.CanonicalOptions(i.Operation, i.Options)
	if err != nil {
		return i, "", err
	}
	i.Options = opts
	slots := []string{"file"}
	if i.Operation == "join" {
		slots = []string{"left", "right"}
	}
	if len(i.Files) != len(slots) {
		return i, "", fail(400, "invalid_files")
	}
	for k, f := range i.Files {
		if f.Slot != slots[k] || f.Bytes <= 0 || f.Bytes > tabular.MaxFile || !secret(f.SHA256) || f.Mode != "put" && f.Mode != "multipart" {
			return i, "", fail(400, "invalid_files")
		}
	}
	raw, _ := json.Marshal(struct {
		Version int
		Intent  Intent
	}{1, i})
	return i, digest(raw), nil
}
func (e *Engine) AdmissionChallenge(i Intent) (Challenge, error) {
	_, binding, err := canonical(i)
	return Challenge{Mode: "synthetic-hmac-no-funds", Stage: "admission", Resource: "/csv/uploads", Binding: binding, Amount: "mock:1", Expires: e.now() + 180}, err
}
func (e *Engine) Admit(i Intent, proof, idem, recovery string) (Admission, error) {
	var out Admission
	intent, binding, err := canonical(i)
	if err != nil {
		return out, err
	}
	challenge, _ := e.AdmissionChallenge(intent)
	challenge.Binding = "" // Authenticate owner/nonce first so an existing key conflict returns 409.
	claim, err := e.Provider.Verify(proof, challenge, true, e.Now())
	if err != nil {
		return out, err
	}
	if !secret(idem) || !secret(recovery) {
		return out, fail(400, "invalid_recovery_fields")
	}
	err = e.Store.tx(true, func(d *database) error {
		key := keyed(d.Key, "idempotency-v1", claim.Owner, idem)
		nonce := keyed(d.Key, "admission-nonce-v1", claim.Owner, claim.Nonce)
		recoveryHash := keyed(d.Key, "recovery-v1", recovery)
		var j *job
		if id := d.Idempotency[key]; id != "" {
			j = d.Jobs[id]
			if j.Binding != binding || j.Nonce != claim.Nonce || !same(j.RecoveryHash, recoveryHash) {
				return fail(409, "binding_conflict")
			}
		} else {
			if claim.Binding != binding {
				return fail(402, "invalid_mock_payment")
			}
			if claim.Expires <= e.now() {
				return fail(402, "admission_expired")
			}
			if d.Nonces[nonce] != "" {
				return fail(409, "admission_nonce_used")
			}
			active := 0
			for _, v := range d.Jobs {
				if v.Artifact != "ERASED" {
					active++
				}
			}
			if d.Quarantine {
				return fail(503, "cleanup_uncertain")
			}
			if active >= 2 || len(d.Jobs) >= maxRecords {
				return fail(429, "capacity_unavailable")
			}
			id := random()
			capability := keyed(d.Key, "capability-v1", id, recovery)
			j = &job{ID: id, Binding: binding, Owner: claim.Owner, Nonce: claim.Nonce, Idempotency: key, RecoveryHash: recoveryHash, CapabilityHash: keyed(d.Key, "cap-verifier-v1", capability), Intent: intent, Artifact: "UPLOAD_INCOMPLETE", Financial: "UNPAID", UploadUntil: e.now() + int64(UploadWindow/time.Second), GrantUntil: e.now() + 300, Files: map[string]*file{}, Downloads: map[string]download{}}
			for _, spec := range intent.Files {
				j.Files[spec.Slot] = &file{Spec: spec, Parts: map[int]part{}}
			}
			d.Jobs[id] = j
			d.Idempotency[key] = id
			d.Nonces[nonce] = id
		}
		out = Admission{JobID: j.ID, Capability: keyed(d.Key, "capability-v1", j.ID, recovery), Expires: j.UploadUntil}
		// Recovery never renews the original grants or expiry and never reopens writes.
		if j.Artifact == "UPLOAD_INCOMPLETE" && e.now() < j.UploadUntil {
			out.Grants = grants(d, j, j.GrantUntil)
		}
		return nil
	})
	return out, err
}
func partBytes(spec FileSpec, n int) int {
	if n < 1 || n > 2 {
		return 0
	}
	if spec.Mode == "put" {
		if n == 1 {
			return spec.Bytes
		}
		return 0
	}
	start := (n - 1) * PartSize
	if start >= spec.Bytes {
		return 0
	}
	return min(PartSize, spec.Bytes-start)
}
func grants(d *database, j *job, until int64) []Grant {
	var result []Grant
	for _, spec := range j.Intent.Files {
		for n := 1; partBytes(spec, n) > 0; n++ {
			token := strconv.FormatInt(until, 10) + "." + keyed(d.Key, "upload-v1", j.ID, j.Epoch, spec.Slot, n, until)
			result = append(result, Grant{Slot: spec.Slot, Part: n, Bytes: partBytes(spec, n), Path: "/csv/uploads/" + j.ID + "/parts/" + spec.Slot + "/" + strconv.Itoa(n), Header: token, Expires: until})
		}
	}
	return result
}
func (e *Engine) Renew(id, cap string) ([]Grant, error) {
	var out []Grant
	err := e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Artifact != "UPLOAD_INCOMPLETE" || e.now() >= j.UploadUntil {
			return fail(410, "upload_closed")
		}
		if j.GrantCalls >= 3 {
			return fail(429, "grant_limit")
		}
		j.GrantCalls++
		j.GrantUntil = min(j.UploadUntil, e.now()+300)
		out = grants(d, j, j.GrantUntil)
		return nil
	})
	return out, err
}
func (e *Engine) Upload(id, slot string, n int, grant string, data []byte) error {
	return e.Store.tx(true, func(d *database) error {
		j := d.Jobs[id]
		if j == nil {
			return fail(404, "not_found")
		}
		f := j.Files[slot]
		if j.Artifact != "UPLOAD_INCOMPLETE" || e.now() >= j.UploadUntil || f == nil {
			return fail(410, "upload_closed")
		}
		p := strings.Split(grant, ".")
		if len(p) != 2 {
			return fail(403, "invalid_upload_grant")
		}
		until, err := strconv.ParseInt(p[0], 10, 64)
		if err != nil || until <= e.now() || until > j.UploadUntil || until > e.now()+300 || !same(p[1], keyed(d.Key, "upload-v1", id, j.Epoch, slot, n, until)) {
			return fail(403, "invalid_upload_grant")
		}
		want := partBytes(f.Spec, n)
		if want == 0 || len(data) != want {
			j.deleting()
			return fail(413, "upload_size_mismatch")
		}
		total := 0
		for _, spec := range j.Intent.Files {
			total += spec.Bytes
		}
		if j.UploadBytes+len(data) > 2*total {
			return fail(429, "upload_retry_limit")
		}
		h := digest(data)
		if old, ok := f.Parts[n]; ok && old.SHA256 != h {
			return fail(409, "immutable_part_conflict")
		}
		j.UploadBytes += len(data)
		f.Parts[n] = part{append([]byte(nil), data...), h}
		return nil
	})
}
func (e *Engine) Finalize(id, cap string) (Status, error) {
	var out Status
	err := e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Artifact == "UPLOAD_VERIFIED" {
			out = j.status()
			return nil
		}
		if j.Artifact != "UPLOAD_INCOMPLETE" || e.now() >= j.UploadUntil {
			return fail(410, "upload_closed")
		}
		for _, spec := range j.Intent.Files {
			f := j.Files[spec.Slot]
			for n := 1; partBytes(spec, n) > 0; n++ {
				if _, ok := f.Parts[n]; !ok {
					return fail(409, "upload_incomplete")
				}
			}
		}
		for _, spec := range j.Intent.Files {
			f := j.Files[spec.Slot]
			var data []byte
			for n := 1; partBytes(spec, n) > 0; n++ {
				data = append(data, f.Parts[n].Bytes...)
			}
			if len(data) != spec.Bytes || digest(data) != spec.SHA256 {
				j.deleting()
				return fail(422, "upload_integrity_mismatch")
			}
			f.Complete = data
			f.Parts = map[int]part{}
		}
		j.Artifact = "UPLOAD_VERIFIED"
		j.Epoch++
		out = j.status()
		return nil
	})
	return out, err
}
func (e *Engine) Submit(id, cap, op string) (Status, error) {
	var out Status
	err := e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Intent.Operation != op {
			return fail(409, "binding_conflict")
		}
		if j.Artifact == "UPLOAD_VERIFIED" && e.now() < j.UploadUntil {
			j.Artifact = "QUEUED"
		} else if j.Artifact != "QUEUED" && j.Artifact != "RUNNING" && j.Artifact != "RESULT_PREPARED" && j.Artifact != "RETRIEVABLE" && j.Artifact != "QUARANTINED" {
			return fail(409, "job_not_submittable")
		}
		out = j.status()
		return nil
	})
	return out, err
}
func (e *Engine) Status(id, cap string) (Status, error) {
	var out Status
	err := e.Store.tx(false, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		out = j.status()
		return nil
	})
	return out, err
}
func (e *Engine) Sweep() error {
	return e.Store.tx(true, func(d *database) error {
		now := e.now()
		for _, j := range d.Jobs {
			if j.ActiveDownload != "" && j.Downloads[j.ActiveDownload].Until <= now {
				j.ActiveDownload = ""
			}
			if j.Artifact == "ERASED" {
				continue
			}
			if now >= j.expiry() {
				if j.Financial == "SETTLEMENT_PENDING" {
					j.Financial = "PAYMENT_UNKNOWN"
					j.UnknownAt = j.Reservation.Started
					j.Artifact = "QUARANTINED"
				} else {
					j.deleting()
				}
			}
			if j.Artifact == "DELETING" && j.Token == "" && j.ActiveDownload == "" {
				j.erase()
			}
		}
		return nil
	})
}
func (e *Engine) Cancel(id, cap string) error {
	err := e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		j.Cancel = true
		if j.Financial == "PAYMENT_UNKNOWN" || j.Financial == "SETTLEMENT_PENDING" {
			return nil
		}
		j.deleting()
		return nil
	})
	e.mu.Lock()
	stop := e.cancel[id]
	if stop != nil {
		stop()
	}
	e.mu.Unlock()
	return err
}
func (e *Engine) Ack(id, cap string) error {
	return e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Financial != "PAID" {
			return fail(409, "not_paid")
		}
		j.deleting()
		return nil
	})
}

// RunNext is a durable local outbox consumer: the QUEUED record is authoritative.
// A crash in RUNNING quarantines dispatch rather than risking a second worker.
func (e *Engine) RunNext(ctx context.Context) (bool, error) {
	if err := e.Sweep(); err != nil {
		return false, err
	}
	var id, token string
	var work api.Job
	var specs []FileSpec
	err := e.Store.tx(true, func(d *database) error {
		if d.Quarantine {
			return fail(503, "cleanup_uncertain")
		}
		for _, j := range d.Jobs {
			if j.Token != "" {
				return nil
			}
		}
		ids := make([]string, 0, len(d.Jobs))
		for k := range d.Jobs {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		for _, k := range ids {
			j := d.Jobs[k]
			if j.Artifact != "QUEUED" {
				continue
			}
			id = j.ID
			token = random()
			j.Token = token
			j.Artifact = "RUNNING"
			specs = append([]FileSpec(nil), j.Intent.Files...)
			work = api.Job{Operation: j.Intent.Operation, Options: j.Intent.Options, Inputs: map[string][]byte{}}
			for slot, f := range j.Files {
				work.Inputs[slot] = f.Complete
			}
			break
		}
		return nil
	})
	if err != nil || id == "" {
		return false, err
	}
	workctx, stop := context.WithTimeout(ctx, 35*time.Second)
	defer stop()
	e.mu.Lock()
	e.cancel[id] = stop
	e.mu.Unlock()
	defer func() { e.mu.Lock(); delete(e.cancel, id); e.mu.Unlock() }()
	// Recheck the durable fence after registering cancellation, before dispatch.
	permitted := false
	err = e.Store.tx(false, func(d *database) error {
		j := d.Jobs[id]
		permitted = j.Token == token && !j.Cancel && e.now() < j.UploadUntil
		return nil
	})
	var result tabular.Result
	var runErr error
	if err != nil {
		return true, err
	}
	if permitted {
		for _, spec := range specs {
			if data := work.Inputs[spec.Slot]; len(data) != spec.Bytes || digest(data) != spec.SHA256 {
				runErr = fail(422, "input_integrity_mismatch")
				break
			}
		}
		if runErr == nil && e.Work == nil {
			runErr = errors.New("worker_missing")
		} else if runErr == nil {
			result, runErr = e.Work(workctx, work)
		}
	} else {
		runErr = fail(408, "request_cancelled")
	}
	var encoded []byte
	var manifest *Manifest
	if runErr == nil {
		encoded, manifest, runErr = prepare(result)
	}
	err = e.Store.tx(true, func(d *database) error {
		j := d.Jobs[id]
		if j.Token != token {
			return fail(409, "stale_worker")
		}
		var known *tabular.Error
		if errors.As(runErr, &known) && known.Code == "worker_cleanup_failed" || runErr != nil && !errors.As(runErr, &known) && !isFlowError(runErr) {
			d.Quarantine = true
			j.Quarantined = true
			j.Code = "cleanup_uncertain"
			j.Cancel = true
			return nil
		}
		j.Token = ""
		j.Files = map[string]*file{}
		if j.Cancel || e.now() >= j.UploadUntil {
			j.deleting()
			return nil
		}
		if runErr != nil {
			j.Code = "processing_failed"
			j.deleting()
			return nil
		}
		j.Result = encoded
		j.Manifest = manifest
		j.ResultUntil = e.now() + int64(ResultWindow/time.Second)
		j.Artifact = "RESULT_PREPARED"
		j.Financial = "AWAITING_PAYMENT"
		return nil
	})
	return true, err
}
func isFlowError(err error) bool { var known *Error; return errors.As(err, &known) }
func prepare(result tabular.Result) ([]byte, *Manifest, error) {
	var logical bytes.Buffer
	w := csv.NewWriter(&logical)
	if err := w.Write(result.Columns); err != nil {
		return nil, nil, err
	}
	for _, row := range result.Rows {
		if err := w.Write(row); err != nil {
			return nil, nil, err
		}
		if logical.Len() > tabular.MaxOutput {
			return nil, nil, fail(413, "output_limit")
		}
	}
	w.Flush()
	if w.Error() != nil || logical.Len() > tabular.MaxOutput {
		return nil, nil, fail(413, "output_limit")
	}
	var encoded bytes.Buffer
	z, _ := gzip.NewWriterLevel(&encoded, gzip.BestSpeed)
	if _, err := z.Write(logical.Bytes()); err != nil {
		return nil, nil, err
	}
	if err := z.Close(); err != nil {
		return nil, nil, err
	}
	if encoded.Len() > tabular.MaxOutput {
		return nil, nil, fail(413, "output_limit")
	}
	m := &Manifest{Version: random(), Format: "text/csv", EncodedBytes: encoded.Len(), LogicalBytes: logical.Len(), Rows: result.OutputRows, EncodedSHA256: digest(encoded.Bytes()), LogicalSHA256: digest(logical.Bytes())}
	if err := verify(encoded.Bytes(), m); err != nil {
		return nil, nil, err
	}
	return encoded.Bytes(), m, nil
}
func verify(data []byte, m *Manifest) error {
	if m == nil || len(data) != m.EncodedBytes || digest(data) != m.EncodedSHA256 || m.LogicalBytes > tabular.MaxOutput || m.EncodedBytes > tabular.MaxOutput {
		return fail(503, "artifact_corrupt")
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fail(503, "artifact_corrupt")
	}
	decoded, err := io.ReadAll(io.LimitReader(r, int64(m.LogicalBytes)+1))
	closeErr := r.Close()
	if err != nil || closeErr != nil || len(decoded) != m.LogicalBytes || digest(decoded) != m.LogicalSHA256 {
		return fail(503, "artifact_corrupt")
	}
	return nil
}
