package flow

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Inspect the authoritative on-disk record at emission, proving events are not
// emitted from inside an uncommitted state callback.
type persistedUnknownWriter struct {
	t     *testing.T
	store *Store
	id    string
	bytes.Buffer
}

func (w *persistedUnknownWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"category":"payment_unknown"`)) {
		if err := w.store.tx(false, func(d *database) error {
			j := d.Jobs[w.id]
			if j.Financial != "PAYMENT_UNKNOWN" || j.Reservation.Outcome != "PAYMENT_UNKNOWN" {
				w.t.Error("event preceded durable unknown transition")
			}
			return nil
		}); err != nil {
			w.t.Error(err)
		}
	}
	return w.Buffer.Write(p)
}
func seedPending(t *testing.T, f *fixture) Admission {
	t.Helper()
	a, p := f.prepared()
	err := f.store.tx(true, func(d *database) error {
		j := d.Jobs[a.JobID]
		j.Reservation = &reservation{ID: random(), ProofHash: digest([]byte(p)), Binding: j.paymentBinding(), Outcome: "SETTLEMENT_PENDING", Started: f.now.Unix()}
		j.Financial = "SETTLEMENT_PENDING"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func assertUnknownEvent(t *testing.T, logs string, route, source string, a Admission, f *fixture) {
	t.Helper()
	if strings.Count(logs, `"category":"payment_unknown"`) != 1 {
		t.Fatal("unknown event missing or repeated", logs)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs)), &event); err != nil {
		t.Fatal(err)
	}
	if event["route"] != route || event["source"] != source || event["financial_state"] != "PAYMENT_UNKNOWN" {
		t.Fatal("incorrect recovery labels")
	}
	for _, secret := range []string{a.JobID, a.Capability, f.owner, f.nonce, f.recovery} {
		if strings.Contains(logs, secret) {
			t.Fatal("recovery event exposed identifiers")
		}
	}
	if count(f) != 0 {
		t.Fatal("recovery initiated settlement")
	}
}
func TestRestartRecoveryEmitsOnePostPersistUnknownEvent(t *testing.T) {
	f := setup(t)
	a := seedPending(t, f)
	f.store.Close()
	store, err := OpenStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	f.provider.Store = store
	output := &persistedUnknownWriter{t: t, store: store, id: a.JobID}
	logger := slog.New(slog.NewJSONHandler(output, nil))
	f.e, err = NewWithLogger(store, f.provider, f.e.Work, logger)
	if err != nil {
		t.Fatal(err)
	}
	f.e.Now = func() time.Time { return f.now }
	// A second actual restart sees UNKNOWN and must not repeat the transition.
	store.Close()
	store, err = OpenStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	f.provider.Store = store
	output.store = store
	f.e, err = NewWithLogger(store, f.provider, f.e.Work, logger)
	if err != nil {
		t.Fatal(err)
	}
	f.e.Now = func() time.Time { return f.now }
	if err = f.e.Sweep(); err != nil {
		t.Fatal(err)
	}
	assertUnknownEvent(t, output.String(), "job_recovery", "restart_recovery", a, f)
}
func TestExpiryEmitsOnePostPersistUnknownEventAcrossRepeatedSweeps(t *testing.T) {
	f := setup(t)
	a := seedPending(t, f)
	output := &persistedUnknownWriter{t: t, store: f.store, id: a.JobID}
	f.e.Logger = slog.New(slog.NewJSONHandler(output, nil))
	s, err := f.e.Status(a.JobID, a.Capability)
	if err != nil {
		t.Fatal(err)
	}
	f.now = time.Unix(s.Expires, 0)
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f.e.Sweep(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err = f.e.Sweep(); err != nil {
		t.Fatal(err)
	}
	assertUnknownEvent(t, output.String(), "job_expiry", "reservation_expiry", a, f)
}
func TestFailedRecoveryPersistenceDoesNotEmitUnknownEvent(t *testing.T) {
	for _, source := range []string{"restart", "expiry"} {
		t.Run(source, func(t *testing.T) {
			f := setup(t)
			a := seedPending(t, f)
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			f.e.Logger = logger
			s, _ := f.e.Status(a.JobID, a.Capability)
			f.now = time.Unix(s.Expires, 0)
			if err := os.Symlink(filepath.Join(f.root, "control.json"), filepath.Join(f.root, "control.next")); err != nil {
				t.Fatal(err)
			}
			var err error
			if source == "restart" {
				_, err = NewWithLogger(f.store, f.provider, f.e.Work, logger)
			} else {
				err = f.e.Sweep()
			}
			if err == nil || output.Len() != 0 {
				t.Fatal("failed persistence emitted a financial transition")
			}
			if err = f.store.tx(false, func(d *database) error {
				if d.Jobs[a.JobID].Financial != "SETTLEMENT_PENDING" {
					t.Fatal("failed write changed authoritative state")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
