package flow

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pdfservice/internal/csvtabular"
	"pdfservice/prototypes/csv/internal/api"
)

type fixture struct {
	t                                 *testing.T
	root                              string
	store                             *Store
	e                                 *Engine
	provider                          *MockProvider
	now                               time.Time
	key, owner, nonce, idem, recovery string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	root, err := os.MkdirTemp("", "utils-csv-flow-test-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, root: root, now: time.Unix(1800000000, 0), key: random(), owner: random(), nonce: random(), idem: random(), recovery: random()}
	t.Cleanup(func() {
		if f.store != nil {
			f.store.Close()
		}
		if err := exec.Command("trash", root).Run(); err != nil {
			t.Error("test scratch cleanup failed")
		}
	})
	f.reopen()
	return f
}
func (f *fixture) reopen() {
	f.t.Helper()
	if f.store != nil {
		f.store.Close()
	}
	var err error
	f.store, err = OpenStore(f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	f.provider = &MockProvider{Store: f.store, Key: f.key}
	f.e, err = New(f.store, f.provider, func(_ context.Context, j api.Job) (tabular.Result, error) {
		return tabular.Execute(j.Operation, j.Options, j.Inputs)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.e.Now = func() time.Time { return f.now }
}
func intentFor(op string, data map[string][]byte, mode string) Intent {
	opts := map[string]string{"transform": `{"column":"v","op":"lower"}`, "dedupe": `{"key_columns":["id"],"keep":"first"}`, "join": `{"left_key_columns":["id"],"right_key_columns":["id"],"type":"inner"}`, "aggregate": `{"group_columns":[],"metrics":[{"name":"count","op":"count_rows"}]}`}
	i := Intent{Operation: op, Options: json.RawMessage(opts[op]), Delivery: "gzip"}
	slots := []string{"file"}
	if op == "join" {
		slots = []string{"left", "right"}
	}
	for _, slot := range slots {
		i.Files = append(i.Files, FileSpec{Slot: slot, Bytes: len(data[slot]), SHA256: digest(data[slot]), Mode: mode})
	}
	return i
}
func (f *fixture) proof(c Challenge) string {
	return SignMock(f.key, Claims{Stage: c.Stage, Owner: f.owner, Nonce: f.nonce, Resource: c.Resource, Binding: c.Binding, Amount: c.Amount, Expires: c.Expires})
}
func (f *fixture) admit(i Intent) (Admission, string) {
	f.t.Helper()
	c, err := f.e.AdmissionChallenge(i)
	if err != nil {
		f.t.Fatal(err)
	}
	p := f.proof(c)
	a, err := f.e.Admit(i, p, f.idem, f.recovery)
	if err != nil {
		f.t.Fatal(err)
	}
	return a, p
}
func (f *fixture) upload(a Admission, data map[string][]byte) {
	f.t.Helper()
	for _, g := range a.Grants {
		start := 0
		if g.Part > 1 {
			start = (g.Part - 1) * PartSize
		}
		if err := f.e.Upload(a.JobID, g.Slot, g.Part, g.Header, data[g.Slot][start:start+g.Bytes]); err != nil {
			f.t.Fatal(err)
		}
	}
}
func (f *fixture) prepared() (Admission, string) {
	f.t.Helper()
	data := map[string][]byte{"file": []byte("id,v\n1,HELLO\n2,WORLD\n")}
	i := intentFor("transform", data, "put")
	a, _ := f.admit(i)
	f.upload(a, data)
	if _, err := f.e.Finalize(a.JobID, a.Capability); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.e.Submit(a.JobID, a.Capability, "transform"); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.e.RunNext(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	c, err := f.e.PaymentChallenge(a.JobID, a.Capability)
	if err != nil {
		f.t.Fatal(err)
	}
	return a, f.proof(c)
}
func code(t *testing.T, err error, want string) {
	t.Helper()
	var known *Error
	if !errors.As(err, &known) || known.Code != want {
		t.Fatalf("got %v want %s", err, want)
	}
}
func count(f *fixture) int {
	n := 0
	err := f.store.tx(false, func(d *database) error { n = d.SettlementCalls; return nil })
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}
func TestAdmissionRecoveryStrictBindingAndNoStoredSecrets(t *testing.T) {
	f := setup(t)
	data := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	i := intentFor("transform", data, "put")
	if _, err := f.e.AdmissionChallenge(i); err != nil {
		t.Fatal(err)
	}
	_ = f.store.tx(false, func(d *database) error {
		if len(d.Jobs) != 0 {
			t.Fatal("quote allocated a job")
		}
		return nil
	})
	a, p := f.admit(i)
	if count(f) != 0 {
		t.Fatal("admission settled")
	}
	oldGrant := a.Grants[0]
	f.now = f.now.Add(4 * time.Minute)
	f.reopen()
	b, err := f.e.Admit(i, p, f.idem, f.recovery)
	if err != nil || b.Capability != a.Capability || b.JobID != a.JobID || b.Expires != a.Expires || b.Grants[0] != oldGrant {
		t.Fatal("lost-response recovery changed identity or clocks", err)
	}
	_, err = f.e.Admit(i, p, f.idem, random())
	code(t, err, "binding_conflict")
	changed := i
	changed.Options = json.RawMessage(`{"column":"v","op":"upper"}`)
	_, err = f.e.Admit(changed, p, f.idem, f.recovery)
	if err == nil {
		t.Fatal("changed binding accepted")
	}
	_, err = f.e.Admit(i, p, random(), f.recovery)
	code(t, err, "admission_expired")
	_, err = f.e.Status(a.JobID, "")
	code(t, err, "not_found")
	raw, err := os.ReadFile(filepath.Join(f.root, "control.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.recovery, a.Capability, p, oldGrant.Header} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("raw secret persisted")
		}
	}
}
func TestConcurrentAdmissionNonceAndCanonicalOptions(t *testing.T) {
	f := setup(t)
	data := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	i := intentFor("transform", data, "put")
	a, p := f.admit(i)
	i.Options = json.RawMessage(" {\"op\":\"lower\", \"column\":\"v\"} ")
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := f.e.Admit(i, p, f.idem, f.recovery)
			if err != nil || b.JobID != a.JobID {
				t.Error("duplicate admission", err)
			}
		}()
	}
	wg.Wait()
	_, err := f.e.Admit(i, p, random(), f.recovery)
	code(t, err, "admission_nonce_used")
	i.Options = json.RawMessage(`{"column":"v","column":"id","op":"lower"}`)
	if _, err = f.e.AdmissionChallenge(i); err == nil {
		t.Fatal("duplicate option accepted")
	}
}
func TestMultipartFinalizeImmutableLateWritesAndMismatch(t *testing.T) {
	f := setup(t)
	data := map[string][]byte{"file": []byte("id,v\n" + strings.Repeat("1,A\n", (PartSize/4)+1))}
	i := intentFor("transform", data, "multipart")
	a, _ := f.admit(i)
	if len(a.Grants) != 2 {
		t.Fatal("multipart plan")
	}
	if err := f.e.Upload(a.JobID, "file", 1, a.Grants[0].Header, data["file"][:PartSize]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Finalize(a.JobID, a.Capability); err == nil {
		t.Fatal("incomplete finalized")
	}
	if err := f.e.Upload(a.JobID, "file", 2, a.Grants[1].Header, data["file"][PartSize:]); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.e.Finalize(a.JobID, a.Capability); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	err := f.e.Upload(a.JobID, "file", 2, a.Grants[1].Header, data["file"][PartSize:])
	code(t, err, "upload_closed")
	if err = f.e.Cancel(a.JobID, a.Capability); err != nil {
		t.Fatal(err)
	}
	err = f.e.Upload(a.JobID, "file", 1, a.Grants[0].Header, data["file"][:PartSize])
	code(t, err, "upload_closed")
	f.nonce = random()
	f.idem = random()
	small := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	i = intentFor("transform", small, "put")
	i.Files[0].SHA256 = random()
	b, _ := f.admit(i)
	f.upload(b, small)
	_, err = f.e.Finalize(b.JobID, b.Capability)
	code(t, err, "upload_integrity_mismatch")
	s, _ := f.e.Status(b.JobID, b.Capability)
	if s.Artifact != "ERASED" || count(f) != 0 {
		t.Fatal(s)
	}
}
func TestFixedGrantExpiryAndInputCorruption(t *testing.T) {
	f := setup(t)
	data := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	a, _ := f.admit(intentFor("transform", data, "put"))
	f.now = f.now.Add(300 * time.Second)
	err := f.e.Upload(a.JobID, "file", 1, a.Grants[0].Header, data["file"])
	code(t, err, "invalid_upload_grant")
	grants, err := f.e.Renew(a.JobID, a.Capability)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.e.Upload(a.JobID, "file", 1, grants[0].Header, data["file"]); err != nil {
		t.Fatal(err)
	}
	_ = f.store.tx(true, func(d *database) error {
		d.Jobs[a.JobID].Files["file"].Parts[1] = part{Bytes: []byte("corrupt")}
		return nil
	})
	_, err = f.e.Finalize(a.JobID, a.Capability)
	code(t, err, "upload_integrity_mismatch")
}
func TestWorkerOneDispatchCancellationAndStaleCompletion(t *testing.T) {
	f := setup(t)
	data := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	a, _ := f.admit(intentFor("transform", data, "put"))
	f.upload(a, data)
	f.e.Finalize(a.JobID, a.Capability)
	f.e.Submit(a.JobID, a.Capability, "transform")
	var calls atomic.Int32
	started := make(chan struct{})
	f.e.Work = func(ctx context.Context, j api.Job) (tabular.Result, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return tabular.Result{}, &tabular.Error{Status: 408, Code: "request_cancelled"}
	}
	done := make(chan error, 1)
	go func() { _, err := f.e.RunNext(context.Background()); done <- err }()
	<-started
	f.e.Submit(a.JobID, a.Capability, "transform")
	ran, err := f.e.RunNext(context.Background())
	if err != nil || ran {
		t.Fatal("duplicate worker")
	}
	if err = f.e.Cancel(a.JobID, a.Capability); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	s, _ := f.e.Status(a.JobID, a.Capability)
	if calls.Load() != 1 || s.Artifact != "ERASED" || count(f) != 0 {
		t.Fatal(s)
	}
}
func TestRestartRunningBlocksReplacement(t *testing.T) {
	f := setup(t)
	a, _ := f.prepared()
	_ = f.store.tx(true, func(d *database) error { j := d.Jobs[a.JobID]; j.Artifact = "RUNNING"; j.Token = random(); return nil })
	f.reopen()
	if _, err := f.e.RunNext(context.Background()); err == nil {
		t.Fatal("uncertain worker replaced")
	}
	s, _ := f.e.Status(a.JobID, a.Capability)
	if s.Code != "cleanup_uncertain" {
		t.Fatal(s)
	}
}
func TestUnknownPaymentReconcileAndNoSecondChargeAcrossRestart(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	if count(f) != 0 {
		t.Fatal("early settlement")
	}
	f.provider.Fault = "accepted-reply-lost"
	s, err := f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	if err != nil || s.Financial != "PAYMENT_UNKNOWN" || count(f) != 1 {
		t.Fatal(s, err)
	}
	if _, err = f.e.InspectResult(a.JobID, a.Capability); err == nil {
		t.Fatal("unknown result leaked")
	}
	if _, err = f.e.PaymentChallenge(a.JobID, a.Capability); err == nil {
		t.Fatal("new challenge while unknown")
	}
	f.reopen()
	if _, err = f.e.Pay(context.Background(), a.JobID, a.Capability, p); err != nil {
		t.Fatal(err)
	}
	if count(f) != 1 {
		t.Fatal("settled twice")
	}
	f.now = f.now.Add(time.Hour)
	s, err = f.e.Reconcile(context.Background(), a.JobID, a.Capability)
	if err != nil || s.Financial != "PAID" || s.Artifact != "RETRIEVABLE" || s.Expires != f.now.Add(ResultWindow).Unix() {
		t.Fatal(s, err)
	}
	if count(f) != 1 {
		t.Fatal("reconciliation charged")
	}
}
func TestUnknownDeadlineEraseAndLatePaidRemedy(t *testing.T) {
	for _, offset := range []time.Duration{UnknownWindow - time.Second, UnknownWindow} {
		t.Run(offset.String(), func(t *testing.T) {
			f := setup(t)
			a, p := f.prepared()
			f.provider.Fault = "accepted-reply-lost"
			f.e.Pay(context.Background(), a.JobID, a.Capability, p)
			f.now = f.now.Add(offset)
			if err := f.e.Sweep(); err != nil {
				t.Fatal(err)
			}
			s, err := f.e.Reconcile(context.Background(), a.JobID, a.Capability)
			if err != nil {
				t.Fatal(err)
			}
			if offset < UnknownWindow {
				if s.Artifact != "RETRIEVABLE" {
					t.Fatal(s)
				}
			} else if s.Artifact != "ERASED" || !s.Remedy || s.Financial != "PAID" {
				t.Fatal(s)
			}
		})
	}
}
func TestDefinitiveRejectionAndCorruptGzipNeverRelease(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	_ = f.store.tx(true, func(d *database) error { j := d.Jobs[a.JobID]; j.Result[len(j.Result)-1] ^= 1; return nil })
	if _, err := f.e.Pay(context.Background(), a.JobID, a.Capability, p); err == nil || count(f) != 0 {
		t.Fatal("corrupt artifact settled")
	}
	f = setup(t)
	a, p = f.prepared()
	f.provider.Fault = "reject"
	s, err := f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	if err != nil || s.Financial != "UNPAID" || s.Artifact != "ERASED" || count(f) != 1 {
		t.Fatal(s, err)
	}
	f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	if count(f) != 1 {
		t.Fatal("rejected proof retried")
	}
}

type crashProvider struct {
	base  *MockProvider
	store *Store
}

func (c crashProvider) Verify(p string, w Challenge, a bool, n time.Time) (Claims, error) {
	return c.base.Verify(p, w, a, n)
}
func (c crashProvider) Lookup(ctx context.Context, id string) (string, error) {
	return c.base.Lookup(ctx, id)
}
func (c crashProvider) Settle(ctx context.Context, id string, claim Claims) (string, error) {
	v, e := c.base.Settle(ctx, id, claim)
	c.store.Close()
	return v, e
}
func TestCrashAfterProviderBeforePaidWrite(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	f.e.Provider = crashProvider{f.provider, f.store}
	if _, err := f.e.Pay(context.Background(), a.JobID, a.Capability, p); err == nil {
		t.Fatal("closed-state write succeeded")
	}
	f.reopen()
	s, _ := f.e.Status(a.JobID, a.Capability)
	if s.Financial != "PAYMENT_UNKNOWN" {
		t.Fatal(s)
	}
	s, err := f.e.Reconcile(context.Background(), a.JobID, a.Capability)
	if err != nil || s.Financial != "PAID" || count(f) != 1 {
		t.Fatal(s, err)
	}
}
func TestCrashBeforeProviderNeverBlindRetries(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	_ = f.store.tx(true, func(d *database) error {
		j := d.Jobs[a.JobID]
		j.Reservation = &reservation{ID: random(), ProofHash: digest([]byte(p)), Started: f.now.Unix(), Binding: j.paymentBinding(), Outcome: "SETTLEMENT_PENDING"}
		j.Financial = "SETTLEMENT_PENDING"
		return nil
	})
	f.reopen()
	s, err := f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	if err != nil || s.Financial != "PAYMENT_UNKNOWN" || count(f) != 0 {
		t.Fatal(s, err)
	}
	s, err = f.e.Reconcile(context.Background(), a.JobID, a.Capability)
	if err != nil || s.Financial != "PAYMENT_UNKNOWN" || count(f) != 0 {
		t.Fatal(s, err)
	}
}
func TestDownloadRangesBudgetReplayAckAndExpiry(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	s, err := f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	if err != nil {
		t.Fatal(err)
	}
	m := s.Manifest
	first := random()
	d, err := f.e.BeginDownload(a.JobID, a.Capability, first, "bytes=0-9")
	if err != nil || len(d.Data) != 10 {
		t.Fatal(err)
	}
	if _, err = f.e.BeginDownload(a.JobID, a.Capability, random(), "bytes=5-14"); err == nil {
		t.Fatal("concurrent download")
	}
	f.e.EndDownload(a.JobID, d.Lease)
	_, err = f.e.BeginDownload(a.JobID, a.Capability, first, "")
	code(t, err, "attempt_replayed")
	f.reopen()
	s, _ = f.e.Status(a.JobID, a.Capability)
	if s.DownloadRemaining != 3*m.EncodedBytes-10 {
		t.Fatal("disconnect refunded bytes", s)
	}
	d, err = f.e.BeginDownload(a.JobID, a.Capability, random(), "bytes=10-")
	if err != nil {
		t.Fatal(err)
	}
	f.e.EndDownload(a.JobID, d.Lease)
	d, err = f.e.BeginDownload(a.JobID, a.Capability, random(), "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(bytes.NewReader(d.Data))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	if err != nil || string(raw) != "id,v\n1,hello\n2,world\n" {
		t.Fatal("wrong output")
	}
	r.Close()
	f.e.EndDownload(a.JobID, d.Lease)
	d, err = f.e.BeginDownload(a.JobID, a.Capability, random(), "")
	if err != nil {
		t.Fatal(err)
	}
	f.e.EndDownload(a.JobID, d.Lease)
	_, err = f.e.BeginDownload(a.JobID, a.Capability, random(), "bytes=0-0")
	code(t, err, "download_budget_exhausted")
	if err = f.e.Acknowledge(a.JobID, a.Capability, m.Version, m.EncodedSHA256); err != nil {
		t.Fatal(err)
	}
	s, _ = f.e.Status(a.JobID, a.Capability)
	if s.Artifact != "ERASED" {
		t.Fatal(s)
	}
	if _, err = f.e.InspectResult(a.JobID, a.Capability); err == nil {
		t.Fatal("acked content retained")
	}
}
func TestStoreExclusiveOwnerSymlinksAndAggregateCapacity(t *testing.T) {
	f := setup(t)
	if another, err := OpenStore(f.root); err == nil {
		another.Close()
		t.Fatal("second writer")
	}
	if err := f.store.tx(true, func(d *database) error { d.Provider["oversize"] = strings.Repeat("x", snapshotLimit); return nil }); err == nil {
		t.Fatal("oversize snapshot written")
	}
	for _, name := range []string{"control.json", "control.next"} {
		info, err := os.Stat(filepath.Join(f.root, name))
		if err == nil && info.Size() > snapshotLimit {
			t.Fatal("state cap")
		}
	}
	f.store.Close()
	if err := os.Symlink(filepath.Join(f.root, "control.json"), filepath.Join(f.root, "link")); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenStore(filepath.Join(f.root, "link")); err == nil {
		store.Close()
		t.Fatal("symlink directory")
	}
}
func TestUploadExpiresCannotRecreateAndNoWindowExtension(t *testing.T) {
	f := setup(t)
	data := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	a, p := f.admit(intentFor("transform", data, "put"))
	f.now = f.now.Add(UploadWindow)
	f.e.Sweep()
	err := f.e.Upload(a.JobID, "file", 1, a.Grants[0].Header, data["file"])
	code(t, err, "upload_closed")
	b, err := f.e.Admit(intentFor("transform", data, "put"), p, f.idem, f.recovery)
	if err != nil || len(b.Grants) != 0 || b.Expires != a.Expires {
		t.Fatal("recovery extended upload", err)
	}
}

func TestOwnerBindingTamperAndStaleWorkerFence(t *testing.T) {
	f := setup(t)
	data := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	i := intentFor("transform", data, "put")
	a, p := f.admit(i)
	changed := i
	changed.Options = json.RawMessage(`{"column":"v","op":"upper"}`)
	_, err := f.e.Admit(changed, p, f.idem, f.recovery)
	code(t, err, "binding_conflict")
	f.upload(a, data)
	f.e.Finalize(a.JobID, a.Capability)
	f.e.Submit(a.JobID, a.Capability, "transform")
	// Corruption after successful finalize must be detected before parser dispatch.
	_ = f.store.tx(true, func(d *database) error { d.Jobs[a.JobID].Files["file"].Complete = []byte("id,v\n1,B\n"); return nil })
	called := false
	f.e.Work = func(context.Context, api.Job) (tabular.Result, error) { called = true; return tabular.Result{}, nil }
	f.e.RunNext(context.Background())
	if called || count(f) != 0 {
		t.Fatal("corrupted immutable input dispatched")
	}
	f = setup(t)
	a, _ = f.admit(i)
	f.upload(a, data)
	f.e.Finalize(a.JobID, a.Capability)
	f.e.Submit(a.JobID, a.Capability, "transform")
	f.e.Work = func(_ context.Context, j api.Job) (tabular.Result, error) {
		_ = f.store.tx(true, func(d *database) error { d.Jobs[a.JobID].Token = random(); return nil })
		return tabular.Execute(j.Operation, j.Options, j.Inputs)
	}
	_, err = f.e.RunNext(context.Background())
	code(t, err, "stale_worker")
	s, _ := f.e.Status(a.JobID, a.Capability)
	if s.Financial != "UNPAID" || s.Manifest != nil || count(f) != 0 {
		t.Fatal("stale result published")
	}
}
func TestExactSnapshotBudgetPreservesPriorState(t *testing.T) {
	f := setup(t)
	size := 0
	_ = f.store.tx(false, func(d *database) error {
		d.Provider["padding"] = ""
		raw, _ := json.Marshal(d)
		size = snapshotLimit - len(raw)
		return nil
	})
	err := f.store.tx(true, func(d *database) error { d.Provider["padding"] = strings.Repeat("x", size); return nil })
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(f.root, "control.json"))
	if err != nil || info.Size() != snapshotLimit {
		t.Fatal("exact cap", err)
	}
	err = f.store.tx(true, func(d *database) error { d.Provider["padding"] += "x"; return nil })
	if err == nil {
		t.Fatal("one byte over accepted")
	}
	_ = f.store.tx(false, func(d *database) error {
		if len(d.Provider["padding"]) != size {
			t.Fatal("failed write replaced authoritative state")
		}
		return nil
	})
	// Force a failed staged write after preflight. The old snapshot must survive.
	f.store.tx(true, func(d *database) error { delete(d.Provider, "padding"); return nil })
	if err = os.Symlink(filepath.Join(f.root, "control.json"), filepath.Join(f.root, "control.next")); err != nil {
		t.Fatal(err)
	}
	err = f.store.tx(true, func(d *database) error { d.Provider["should_not_commit"] = "no"; return nil })
	if err == nil {
		t.Fatal("symlink next accepted")
	}
	_ = f.store.tx(false, func(d *database) error {
		if d.Provider["should_not_commit"] != "" {
			t.Fatal("failed staged write damaged state")
		}
		return nil
	})
}
func TestResultWindowAndActiveDownloadFencing(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	dl, err := f.e.BeginDownload(a.JobID, a.Capability, random(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.e.Cancel(a.JobID, a.Capability); err != nil {
		t.Fatal(err)
	}
	s, _ := f.e.Status(a.JobID, a.Capability)
	if s.Artifact != "DELETING" || f.e.DownloadAllowed(a.JobID, dl.Lease) {
		t.Fatal("active transfer not fenced")
	}
	f.e.EndDownload(a.JobID, dl.Lease)
	s, _ = f.e.Status(a.JobID, a.Capability)
	if s.Artifact != "ERASED" {
		t.Fatal(s)
	}
	f = setup(t)
	a, p = f.prepared()
	f.now = f.now.Add(ResultWindow - 299*time.Second)
	if _, err = f.e.Pay(context.Background(), a.JobID, a.Capability, p); err == nil || count(f) != 0 {
		t.Fatal("short retrieval window settled")
	}
	f.now = f.now.Add(299 * time.Second)
	f.e.Sweep()
	s, _ = f.e.Status(a.JobID, a.Capability)
	if s.Artifact != "ERASED" {
		t.Fatal(s)
	}
}

func TestConcurrentRangesDebitOnlyOneActiveStream(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	var wg sync.WaitGroup
	var success atomic.Int32
	start := make(chan struct{})
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := f.e.BeginDownload(a.JobID, a.Capability, random(), "bytes=0-9"); err == nil {
				success.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	s, _ := f.e.Status(a.JobID, a.Capability)
	if success.Load() != 1 || s.DownloadRemaining != 3*s.EncodedBytes-10 {
		t.Fatal("overlapping stream reservations were not atomic")
	}
}
