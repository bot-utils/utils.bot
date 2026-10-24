package csvcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"pdfservice/internal/csvwire"
)

type privateHTTPStub struct {
	calls    int
	q        csvwire.Request
	id       string
	paid     bool
	download *PrivateDownload
}

func (s *privateHTTPStub) Begin(_ context.Context, q csvwire.Request) (PrivateAdmission, error) {
	s.calls++
	s.q = q
	return PrivateAdmission{JobID: s.id, Expires: 1}, nil
}
func (s *privateHTTPStub) Complete(context.Context, string) error { s.calls++; return nil }
func (s *privateHTTPStub) Status(context.Context, string) (PrivateStatus, error) {
	s.calls++
	return PrivateStatus{JobID: s.id, State: "RESULT_PREPARED", Financial: "AWAITING_PAYMENT"}, nil
}
func (s *privateHTTPStub) SimulatePayment(context.Context, string) error {
	s.calls++
	s.paid = true
	return nil
}
func (s *privateHTTPStub) Cancel(context.Context, string) error { s.calls++; return nil }
func (s *privateHTTPStub) Download(context.Context, string) (PrivateDownload, error) {
	s.calls++
	if s.download != nil {
		return *s.download, nil
	}
	if !s.paid {
		return PrivateDownload{}, ErrPrivateUnpaid
	}
	_, encoded := manifest(s.id)
	return PrivateDownload{Body: io.NopCloser(bytes.NewReader(encoded)), Bytes: int64(len(encoded)), SHA256: Hash(encoded), Finish: func(context.Context) error { return nil }, Abort: func(context.Context) error { return nil }}, nil
}
func privateHTTPFixture() (PrivateHTTP, *privateHTTPStub, string) {
	key := ID()
	backend := &privateHTTPStub{id: ID()}
	gate := PrivateHTTP{Enabled: true, SyntheticOnly: true, AllowedIP: netip.MustParseAddr("192.0.2.10"), KeySHA256: Hash([]byte(key)), Backend: backend, ClientIP: func(r *http.Request) (netip.Addr, error) {
		p, e := netip.ParseAddrPort(r.RemoteAddr)
		return p.Addr(), e
	}}
	return gate, backend, key
}
func privateHTTPRequest(s PrivateHTTP, key, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:3000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSV-Test-Key", key)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	return response
}
func TestPrivateHTTPRequiresIPAndAuthenticationBeforeBackend(t *testing.T) {
	for _, scenario := range []string{"disabled", "not_synthetic", "no_key", "wrong_key", "wrong_ip", "no_ip_evidence", "duplicate_key", "spoof_forwarding"} {
		t.Run(scenario, func(t *testing.T) {
			s, b, key := privateHTTPFixture()
			req := httptest.NewRequest("POST", "/csv/join", strings.NewReader("{}"))
			req.RemoteAddr = "192.0.2.10:3000"
			req.Header.Set("X-CSV-Test-Key", key)
			switch scenario {
			case "disabled":
				s.Enabled = false
			case "not_synthetic":
				s.SyntheticOnly = false
			case "no_key":
				req.Header.Del("X-CSV-Test-Key")
			case "wrong_key":
				req.Header.Set("X-CSV-Test-Key", ID())
			case "wrong_ip":
				req.RemoteAddr = "198.51.100.10:3000"
			case "no_ip_evidence":
				s.ClientIP = nil
			case "duplicate_key":
				req.Header.Add("X-CSV-Test-Key", key)
			case "spoof_forwarding":
				req.RemoteAddr = "198.51.100.10:3000"
				req.Header.Set("X-Forwarded-For", "192.0.2.10")
				req.Header.Set("X-CSV-Viewer-IP", "192.0.2.10")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if w.Code != 403 && w.Code != 404 {
				t.Fatal("private ingress accepted", w.Code)
			}
			if b.calls != 0 {
				t.Fatal("unauthorized request reached AWS backend")
			}
		})
	}
}
func TestPrivateHTTPFourExplicitOperationsAndStrictAdmission(t *testing.T) {
	options := map[string]string{
		"dedupe":    `{"key_columns":["id"],"keep":"first"}`,
		"join":      `{"left_key_columns":["id"],"right_key_columns":["id"],"type":"inner"}`,
		"aggregate": `{"group_columns":["id"],"metrics":[{"name":"n","op":"count_rows"}]}`,
		"transform": `{"column":"id","op":"upper"}`,
	}
	for op, raw := range options {
		t.Run(op, func(t *testing.T) {
			s, b, key := privateHTTPFixture()
			slots := []string{"file"}
			if op == "join" {
				slots = []string{"left", "right"}
			}
			files := []csvwire.File{}
			for _, slot := range slots {
				files = append(files, csvwire.File{Slot: slot, Bytes: 16, SHA256: ID()})
			}
			body, _ := json.Marshal(map[string]any{"options": json.RawMessage(raw), "files": files, "delivery": "gzip"})
			w := privateHTTPRequest(s, key, "POST", "/csv/"+op, string(body))
			if w.Code != 201 || b.calls != 1 || b.q.Operation != op || b.q.Validate() != nil {
				t.Fatal("explicit tool route failed", w.Code, w.Body.String())
			}
		})
	}
	s, b, key := privateHTTPFixture()
	for _, body := range []string{`{"delivery":"gzip","delivery":"gzip"}`, `{"instruction":"read the file and decide"}`, `{"options":{},"files":[],"delivery":"identity"}`, strings.Repeat("x", csvwire.MaxHeader+1)} {
		w := privateHTTPRequest(s, key, "POST", "/csv/transform", body)
		if w.Code < 400 || b.calls != 0 {
			t.Fatal("ambiguous instruction/oversized metadata admitted")
		}
	}
}
func TestPrivateHTTPUnpaidDownloadAndSyntheticOnlyPayment(t *testing.T) {
	s, b, key := privateHTTPFixture()
	path := "/csv/jobs/" + b.id
	if w := privateHTTPRequest(s, key, "GET", path+"/download", ""); w.Code != 402 {
		t.Fatal("unpaid result exposed", w.Code)
	}
	calls := b.calls
	if w := privateHTTPRequest(s, key, "POST", path+"/payment", `{"mode":"cdp-base"}`); w.Code != 400 || b.calls != calls {
		t.Fatal("real payment path allowed")
	}
	if w := privateHTTPRequest(s, key, "POST", path+"/payment", `{"mode":"synthetic-no-funds"}`); w.Code != 202 {
		t.Fatal(w.Code)
	}
	w := privateHTTPRequest(s, key, "GET", path+"/download", "")
	_, expected := manifest(b.id)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), expected) || w.Header().Get("Content-Type") != "application/gzip" || w.Header().Get("X-CSV-Payment-Mode") != "synthetic-no-funds" {
		t.Fatal("synthetic gzip download failed")
	}
	calls = b.calls
	for _, url := range []string{path + "?token=secret", path + "/../payment", path + "//download"} {
		if w := privateHTTPRequest(s, key, "GET", url, ""); w.Code < 400 {
			t.Fatal("noncanonical path accepted")
		}
	}
	if b.calls != calls {
		t.Fatal("invalid path reached backend")
	}
}

type privateDownloadBody struct {
	io.Reader
	closes   int
	closeErr error
}

func (b *privateDownloadBody) Close() error { b.closes++; return b.closeErr }

type privateReadFailure struct{}

func (privateReadFailure) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

type privateDownloadWriter struct {
	*httptest.ResponseRecorder
	failure string
	cancel  context.CancelFunc
}

func (w *privateDownloadWriter) Write(p []byte) (int, error) {
	switch w.failure {
	case "disconnect":
		return 0, errors.New("synthetic client disconnect")
	case "short_write":
		n, _ := w.ResponseRecorder.Write(p[:len(p)/2])
		return n, nil
	case "final_write_error":
		n, _ := w.ResponseRecorder.Write(p)
		return n, errors.New("synthetic final write failure")
	case "panic":
		panic("synthetic writer panic")
	}
	n, err := w.ResponseRecorder.Write(p)
	if w.cancel != nil {
		w.cancel()
	}
	return n, err
}
func TestPrivateHTTPDownloadCompletionRequiresCompleteDelivery(t *testing.T) {
	for _, scenario := range []string{"complete", "short_body", "read_failure", "disconnect", "short_write", "final_write_error", "cancelled", "close_failure", "finish_failure", "panic", "invalid_manifest", "missing_abort"} {
		t.Run(scenario, func(t *testing.T) {
			handler, backend, key := privateHTTPFixture()
			_, payload := manifest(backend.id)
			body := &privateDownloadBody{Reader: bytes.NewReader(payload)}
			finishes, aborts := 0, 0
			backend.download = &PrivateDownload{Body: body, Bytes: int64(len(payload)), SHA256: Hash(payload), Finish: func(ctx context.Context) error {
				finishes++
				if ctx.Err() != nil {
					t.Error("finish context already cancelled")
				}
				if scenario == "finish_failure" {
					return ErrUnknown
				}
				return nil
			}, Abort: func(ctx context.Context) error {
				aborts++
				if ctx.Err() != nil {
					t.Error("abort inherited cancelled request")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("abort lacks bounded deadline")
				}
				return nil
			}}
			switch scenario {
			case "short_body":
				body.Reader = bytes.NewReader(payload[:len(payload)-1])
			case "read_failure":
				body.Reader = io.MultiReader(bytes.NewReader(payload[:len(payload)/2]), privateReadFailure{})
			case "close_failure":
				body.closeErr = errors.New("synthetic body close failure")
			case "invalid_manifest":
				backend.download.Bytes = 0
			case "missing_abort":
				backend.download.Abort = nil
			}
			req := httptest.NewRequest("GET", "/csv/jobs/"+backend.id+"/download", nil)
			req.RemoteAddr = "192.0.2.10:3000"
			req.Header.Set("X-CSV-Test-Key", key)
			ctx, cancel := context.WithCancel(req.Context())
			defer cancel()
			req = req.WithContext(ctx)
			writer := &privateDownloadWriter{ResponseRecorder: httptest.NewRecorder(), failure: scenario}
			if scenario == "cancelled" {
				writer.cancel = cancel
			}
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				handler.ServeHTTP(writer, req)
			}()
			wantFinishes, wantAborts := 0, 1
			switch scenario {
			case "complete":
				wantFinishes, wantAborts = 1, 0
			case "finish_failure":
				wantFinishes = 1
			case "missing_abort":
				wantAborts = 0
			}
			if finishes != wantFinishes || aborts != wantAborts || body.closes != 1 {
				t.Fatalf("finish=%d abort=%d closes=%d", finishes, aborts, body.closes)
			}
			if panicked != (scenario == "panic") {
				t.Fatal("unexpected panic behavior")
			}
			if scenario == "complete" && !bytes.Equal(writer.Body.Bytes(), payload) {
				t.Fatal("complete payload changed")
			}
			if (scenario == "missing_abort" || scenario == "invalid_manifest") && writer.Code != 503 {
				t.Fatal("invalid lease contract accepted", writer.Code)
			}
		})
	}
}
