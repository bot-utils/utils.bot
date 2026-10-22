package flow

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"utils.bot/csvprototype/internal/api"
)

func request(t *testing.T, h http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	switch v := body.(type) {
	case []byte:
		data = v
	case nil:
	default:
		data, _ = json.Marshal(v)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(data))
	r.RemoteAddr = "127.0.0.1:12345"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func decoded[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal("invalid HTTP reply", w.Code, err)
	}
	return out
}
func runHTTPFlow(t *testing.T, op string, useDocker bool) {
	f := setup(t)
	if useDocker {
		f.e.Work = (api.Docker{Image: "utils-bot-csv-prototype:local"}).Run
	}
	var logs bytes.Buffer
	h := NewHTTP(f.e, true, slog.New(slog.NewJSONHandler(&logs, nil)))
	data := map[string][]byte{"file": []byte("id,v\n1,HELLO\n1,HELLO\n2,WORLD\n")}
	if op == "join" {
		data = map[string][]byte{"left": []byte("id,v\n1,HELLO\n"), "right": []byte("id,other\n1,YES\n")}
	}
	intent := intentFor(op, data, "multipart")
	w := request(t, h, "POST", "/csv/uploads", intent, nil)
	if w.Code != 402 {
		t.Fatal(w.Code, w.Body.String())
	}
	c := decoded[Challenge](t, w)
	proof := f.proof(c)
	headers := map[string]string{"Payment-Signature": proof, "Idempotency-Key": f.idem, "Recovery-Secret": f.recovery}
	w = request(t, h, "POST", "/csv/uploads", intent, headers)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	a := decoded[Admission](t, w)
	cap := map[string]string{"X-Job-Capability": a.Capability}
	for _, g := range a.Grants {
		w = request(t, h, "PUT", g.Path, data[g.Slot], map[string]string{"Content-Type": "application/octet-stream", "X-Upload-Grant": g.Header})
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w = request(t, h, "POST", "/csv/uploads/"+a.JobID+"/finalize", struct{}{}, cap)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/csv/"+op, map[string]string{"job_id": a.JobID}, cap)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	if count(f) != 0 {
		t.Fatal("settlement before result")
	}
	if _, err := f.e.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/csv/jobs/"+a.JobID+"/payment", struct{}{}, cap)
	if w.Code != 402 {
		t.Fatal(w.Code, w.Body.String())
	}
	c = decoded[Challenge](t, w)
	cap["Payment-Signature"] = f.proof(c)
	w = request(t, h, "POST", "/csv/jobs/"+a.JobID+"/payment", struct{}{}, cap)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	s := decoded[Status](t, w)
	if s.Financial != "PAID" || s.Manifest == nil || count(f) != 1 {
		t.Fatal(s)
	}
	delete(cap, "Payment-Signature")
	endpoint := "/csv/jobs/" + a.JobID + "/result.gz"
	w = request(t, h, "HEAD", endpoint, nil, cap)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	tag := w.Header().Get("ETag")
	cap["If-None-Match"] = tag
	w = request(t, h, "GET", endpoint, nil, cap)
	if w.Code != 304 {
		t.Fatal(w.Code)
	}
	delete(cap, "If-None-Match")
	cap["Download-Attempt"] = random()
	cap["Range"] = "bytes=99999999-"
	w = request(t, h, "GET", endpoint, nil, cap)
	if w.Code != 416 {
		t.Fatal(w.Code)
	}
	delete(cap, "Range")
	before, _ := f.e.Status(a.JobID, a.Capability)
	if before.DownloadRemaining != 3*s.Manifest.EncodedBytes {
		t.Fatal("HEAD/304/416 debited")
	}
	cap["Range"] = "bytes=0-9"
	cap["Download-Attempt"] = random()
	w = request(t, h, "GET", endpoint, nil, cap)
	if w.Code != 206 {
		t.Fatal(w.Code)
	}
	encoded := append([]byte(nil), w.Body.Bytes()...)
	cap["Range"] = "bytes=10-"
	cap["Download-Attempt"] = random()
	w = request(t, h, "GET", endpoint, nil, cap)
	if w.Code != 206 {
		t.Fatal(w.Code)
	}
	encoded = append(encoded, w.Body.Bytes()...)
	delete(cap, "Range")
	if digest(encoded) != s.Manifest.EncodedSHA256 {
		t.Fatal("range reassembly changed gzip")
	}
	z, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	z.Close()
	if err != nil || digest(raw) != s.Manifest.LogicalSHA256 {
		t.Fatal("decode integrity")
	}
	cap["Accept-Encoding"] = "gzip"
	cap["Download-Attempt"] = random()
	w = request(t, h, "GET", "/csv/jobs/"+a.JobID+"/result", nil, cap)
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(encoded, w.Body.Bytes()) {
		t.Fatal("transparent route changed bytes")
	}
	ack := map[string]any{"complete": true, "version": s.Manifest.Version, "encoded_sha256": s.Manifest.EncodedSHA256}
	w = request(t, h, "POST", "/csv/jobs/"+a.JobID+"/ack", ack, cap)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	after, _ := f.e.Status(a.JobID, a.Capability)
	if after.Artifact != "ERASED" || count(f) != 1 {
		t.Fatal(after)
	}
	for _, sensitive := range []string{a.JobID, a.Capability, f.recovery, f.owner, f.nonce, proof, "HELLO", s.Manifest.EncodedSHA256} {
		if strings.Contains(logs.String(), sensitive) {
			t.Fatal("sensitive telemetry")
		}
	}
	for _, label := range []string{"admission_quote", "result_challenge", "provider_attempt", "confirmed_paid"} {
		if !strings.Contains(logs.String(), label) {
			t.Fatal("missing event", label)
		}
	}
}
func TestHTTPAllOperations(t *testing.T) {
	for _, op := range []string{"dedupe", "join", "aggregate", "transform"} {
		t.Run(op, func(t *testing.T) { runHTTPFlow(t, op, false) })
	}
}
func TestHTTPGateCanonicalHeadersAndPrivateStatus(t *testing.T) {
	f := setup(t)
	closed := NewHTTP(f.e, false, nil)
	if w := request(t, closed, "GET", "/csv/jobs/unknown", nil, nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
	h := NewHTTP(f.e, true, nil)
	for _, path := range []string{"/csv/uploads?secret=bad", "/csv//uploads", "/csv/%75ploads"} {
		w := request(t, h, "POST", path, struct{}{}, nil)
		if w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	if w := request(t, h, "GET", "/csv/jobs/unknown", nil, nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1/csv/uploads", strings.NewReader("{}"))
	r.RemoteAddr = "203.0.113.1:22"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("POST", "http://127.0.0.1/csv/uploads", strings.NewReader("{}"))
	r.RemoteAddr = "127.0.0.1:22"
	r.Header.Add("Payment-Signature", "one")
	r.Header.Add("Payment-Signature", "two")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

type disconnected struct {
	header http.Header
	writes int
}

func (d *disconnected) Header() http.Header {
	if d.header == nil {
		d.header = http.Header{}
	}
	return d.header
}
func (*disconnected) WriteHeader(int)               {}
func (d *disconnected) Write(p []byte) (int, error) { d.writes++; return 1, io.ErrClosedPipe }
func TestHTTPDisconnectConsumesWholeReservation(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	before, _ := f.e.Status(a.JobID, a.Capability)
	h := NewHTTP(f.e, true, nil)
	r := httptest.NewRequest("GET", "http://127.0.0.1/csv/jobs/"+a.JobID+"/result.gz", nil)
	r.RemoteAddr = "127.0.0.1:4"
	r.Header.Set("X-Job-Capability", a.Capability)
	r.Header.Set("Download-Attempt", random())
	w := &disconnected{}
	h.ServeHTTP(w, r)
	after, _ := f.e.Status(a.JobID, a.Capability)
	if w.writes != 1 || after.DownloadRemaining != before.DownloadRemaining-before.EncodedBytes {
		t.Fatal("ambiguous disconnect refunded")
	}
}
func TestHTTPMalformedProofAndInputSchema(t *testing.T) {
	f := setup(t)
	var logs bytes.Buffer
	h := NewHTTP(f.e, true, slog.New(slog.NewJSONHandler(&logs, nil)))
	data := map[string][]byte{"file": []byte("id,v\n1,A\n")}
	i := intentFor("transform", data, "put")
	w := request(t, h, "POST", "/csv/uploads", i, map[string]string{"Payment-Signature": "secret-proof"})
	if w.Code != 402 || !strings.Contains(logs.String(), "malformed_proof") || strings.Contains(logs.String(), "secret-proof") {
		t.Fatal("proof log boundary")
	}
	raw := []byte(`{"operation":"transform","options":{"column":"v","op":"lower","op":"upper"},"files":[],"delivery":"gzip"}`)
	w = request(t, h, "POST", "/csv/uploads", raw, map[string]string{"Content-Type": "application/json"})
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestHTTPAutomaticGzipClientAndReservationRecovery(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	f.e.Pay(context.Background(), a.JobID, a.Capability, p)
	server := httptest.NewServer(NewHTTP(f.e, true, nil))
	defer server.Close()
	attempt := random()
	req, err := http.NewRequest("GET", server.URL+"/csv/jobs/"+a.JobID+"/result", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Job-Capability", a.Capability)
	req.Header.Set("Download-Attempt", attempt)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !response.Uncompressed || string(body) != "id,v\n1,hello\n2,world\n" {
		t.Fatal("automatic gzip decode failed", err)
	}
	h := NewHTTP(f.e, true, nil)
	w := request(t, h, "GET", "/csv/jobs/"+a.JobID+"/downloads/"+attempt, nil, map[string]string{"X-Job-Capability": a.Capability})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	result := decoded[struct {
		Bytes  int  `json:"reserved_bytes"`
		Active bool `json:"active"`
		Replay bool `json:"stream_replay_allowed"`
	}](t, w)
	s, _ := f.e.Status(a.JobID, a.Capability)
	if result.Bytes != s.EncodedBytes || result.Active || result.Replay || s.DownloadRemaining != 2*s.EncodedBytes {
		t.Fatal("reservation recovery changed budget")
	}
}

func TestHTTPPendingUnknownNeverReportsUnpaidOrStartsDownload(t *testing.T) {
	for _, financial := range []string{"SETTLEMENT_PENDING", "PAYMENT_UNKNOWN"} {
		t.Run(financial, func(t *testing.T) {
			f := setup(t)
			a, p := f.prepared()
			_ = f.store.tx(true, func(d *database) error {
				j := d.Jobs[a.JobID]
				j.Reservation = &reservation{ID: random(), ProofHash: digest([]byte(p)), Started: f.now.Unix(), Outcome: financial}
				j.Financial = financial
				j.UnknownAt = f.now.Unix()
				return nil
			})
			var logs bytes.Buffer
			h := NewHTTP(f.e, true, slog.New(slog.NewJSONHandler(&logs, nil)))
			headers := map[string]string{"X-Job-Capability": a.Capability, "Download-Attempt": random(), "Range": "bytes=0-9", "Accept-Encoding": "gzip"}
			for _, suffix := range []string{"result", "result.gz"} {
				w := request(t, h, "GET", "/csv/jobs/"+a.JobID+"/"+suffix, nil, headers)
				if w.Code != 409 || strings.Contains(w.Body.String(), "result_unpaid") {
					t.Fatal("ambiguous payment mislabeled", w.Code, w.Body.String())
				}
			}
			w := request(t, h, "POST", "/csv/jobs/"+a.JobID+"/payment", struct{}{}, headers)
			if w.Code != 409 {
				t.Fatal("replacement challenge issued", w.Code)
			}
			w = request(t, h, "GET", "/csv/jobs/"+a.JobID, nil, headers)
			if w.Code != 200 || decoded[Status](t, w).Financial != financial {
				t.Fatal("status lost financial state")
			}
			if !strings.Contains(logs.String(), `"financial_state":"`+financial+`"`) || !strings.Contains(logs.String(), `"category":"payment_state_blocked"`) || strings.Contains(logs.String(), "result_unpaid") {
				t.Fatal("financial logs mislabeled")
			}
			s, _ := f.e.Status(a.JobID, a.Capability)
			if s.DownloadRemaining != 3*s.EncodedBytes || count(f) != 0 {
				t.Fatal("unknown started stream or settlement")
			}
		})
	}
}
func TestHTTPReconciliationFinancialCategories(t *testing.T) {
	for _, fault := range []string{"accepted-reply-lost", "rejected-reply-lost", "no-provider-call"} {
		t.Run(fault, func(t *testing.T) {
			f := setup(t)
			a, p := f.prepared()
			if fault == "no-provider-call" {
				_ = f.store.tx(true, func(d *database) error {
					j := d.Jobs[a.JobID]
					j.Reservation = &reservation{ID: random(), ProofHash: digest([]byte(p)), Started: f.now.Unix(), Outcome: "PAYMENT_UNKNOWN"}
					j.Financial = "PAYMENT_UNKNOWN"
					j.UnknownAt = f.now.Unix()
					return nil
				})
			} else {
				f.provider.Fault = fault
				f.e.Pay(context.Background(), a.JobID, a.Capability, p)
			}
			var logs bytes.Buffer
			h := NewHTTP(f.e, true, slog.New(slog.NewJSONHandler(&logs, nil)))
			w := request(t, h, "POST", "/csv/jobs/"+a.JobID+"/reconcile", struct{}{}, map[string]string{"X-Job-Capability": a.Capability})
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			expected := "confirmed_paid"
			if fault == "rejected-reply-lost" {
				expected = "definitive_rejection"
			} else if fault == "no-provider-call" {
				expected = "reconciliation_response"
			}
			if !strings.Contains(logs.String(), `"category":"`+expected+`"`) {
				t.Fatal("reconciliation misclassified", logs.String())
			}
		})
	}
}

func TestHTTPPaymentSyntaxSignatureAndVerifiedRejectionAreDistinct(t *testing.T) {
	f := setup(t)
	a, _ := f.prepared()
	challenge, err := f.e.PaymentChallenge(a.JobID, a.Capability)
	if err != nil {
		t.Fatal(err)
	}
	valid := Claims{Stage: challenge.Stage, Owner: f.owner, Nonce: random(), Resource: challenge.Resource, Binding: challenge.Binding, Amount: challenge.Amount, Expires: challenge.Expires}
	for _, name := range []string{"duplicate", "malformed", "signature", "owner", "binding", "expiry"} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			h := NewHTTP(f.e, true, slog.New(slog.NewJSONHandler(&logs, nil)))
			claim := valid
			expected := "verified_proof_rejected"
			proof := ""
			switch name {
			case "owner":
				claim.Owner = random()
			case "binding":
				claim.Binding = random()
			case "expiry":
				claim.Expires = f.now.Unix() - 1
			}
			proof = SignMock(f.key, claim)
			if name == "malformed" {
				proof = "malformed-proof"
				expected = "malformed_proof"
			}
			if name == "signature" {
				p := strings.Split(proof, ".")
				proof = p[0] + "." + random()
				expected = "invalid_signature"
			}
			if name == "duplicate" {
				expected = "malformed_proof"
			}
			r := httptest.NewRequest("POST", "http://127.0.0.1/csv/jobs/"+a.JobID+"/payment", strings.NewReader("{}"))
			r.RemoteAddr = "127.0.0.1:2"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Job-Capability", a.Capability)
			r.Header.Set("Payment-Signature", proof)
			if name == "duplicate" {
				r.Header.Add("Payment-Signature", proof)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			wantStatus := 402
			if name == "duplicate" {
				wantStatus = 400
			}
			if w.Code != wantStatus || !strings.Contains(logs.String(), `"category":"`+expected+`"`) || strings.Contains(logs.String(), proof) || count(f) != 0 {
				t.Fatal("payment outcome misclassified", w.Code, logs.String())
			}
		})
	}
}

func TestPaymentEventsAreNotRepeatedByPollingOrProofReplay(t *testing.T) {
	f := setup(t)
	a, p := f.prepared()
	var logs bytes.Buffer
	h := NewHTTP(f.e, true, slog.New(slog.NewJSONHandler(&logs, nil)))
	headers := map[string]string{"X-Job-Capability": a.Capability, "Payment-Signature": p}
	path := "/csv/jobs/" + a.JobID
	for n := 0; n < 4; n++ {
		w := request(t, h, "POST", path+"/payment", struct{}{}, headers)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		w = request(t, h, "GET", path, nil, headers)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	delete(headers, "Payment-Signature")
	for n := 0; n < 3; n++ {
		w := request(t, h, "POST", path+"/payment", struct{}{}, headers)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if strings.Count(logs.String(), `"category":"provider_attempt"`) != 1 || strings.Count(logs.String(), `"category":"confirmed_paid"`) != 1 || !strings.Contains(logs.String(), `"category":"job_status","financial_state":"PAID"`) || !strings.Contains(logs.String(), `"category":"payment_replay"`) {
		t.Fatal("poll/replay inflated financial events", logs.String())
	}
}
func TestResultUnpaidHasDistinctAccessCategory(t *testing.T) {
	f := setup(t)
	a, _ := f.prepared()
	var logs bytes.Buffer
	h := NewHTTP(f.e, true, slog.New(slog.NewJSONHandler(&logs, nil)))
	w := request(t, h, "GET", "/csv/jobs/"+a.JobID+"/result.gz", nil, map[string]string{"X-Job-Capability": a.Capability})
	if w.Code != 402 || !strings.Contains(logs.String(), `"category":"result_payment_required"`) || strings.Contains(logs.String(), `"category":"definitive_rejection"`) {
		t.Fatal("result access request misclassified")
	}
}
