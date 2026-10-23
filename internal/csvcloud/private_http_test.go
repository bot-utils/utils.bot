package csvcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"pdfservice/internal/csvwire"
)

type privateHTTPStub struct {
	calls int
	q     csvwire.Request
	id    string
	paid  bool
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
	if !s.paid {
		return PrivateDownload{}, ErrPrivateUnpaid
	}
	_, encoded := manifest(s.id)
	return PrivateDownload{Body: io.NopCloser(bytes.NewReader(encoded)), Bytes: int64(len(encoded)), SHA256: Hash(encoded), Finish: func(context.Context) error { return nil }}, nil
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
