package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"utils.bot/csvprototype/internal/tabular"
)

func direct(ctx context.Context, j Job) (tabular.Result, error) {
	return tabular.Execute(j.Operation, j.Options, j.Inputs)
}
func request(t *testing.T, path, opts string, files map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	p, e := w.CreateFormField("options")
	if e != nil {
		t.Fatal(e)
	}
	io.WriteString(p, opts)
	for name, value := range files {
		p, e := w.CreateFormFile(name, "private-filename-canary.csv")
		if e != nil {
			t.Fatal(e)
		}
		io.WriteString(p, value)
	}
	w.Close()
	r := httptest.NewRequest("POST", "http://127.0.0.1:18082"+path, &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())
	return r
}
func TestMultipartOperationsNeverSpillOrLogCustomerData(t *testing.T) {
	area := t.TempDir()
	t.Setenv("TMPDIR", area)
	var logs bytes.Buffer
	s := New(direct, slog.New(slog.NewJSONHandler(&logs, nil)))
	tests := []struct {
		path, opts string
		files      map[string]string
		wantRows   int
	}{
		{"/csv/dedupe", `{"key_columns":["PRIVATE_HEADER"],"keep":"first"}`, map[string]string{"file": "PRIVATE_HEADER,value\nPRIVATE_KEY,PRIVATE_CONTENT\nPRIVATE_KEY,other\n"}, 1},
		{"/csv/join", `{"left_key_columns":["PRIVATE_HEADER"],"right_key_columns":["PRIVATE_HEADER"],"type":"anti"}`, map[string]string{"left": "PRIVATE_HEADER\nPRIVATE_KEY\n", "right": "PRIVATE_HEADER\nother\n"}, 1},
		{"/csv/aggregate", `{"metrics":[{"name":"total","op":"sum","column":"PRIVATE_HEADER"}]}`, map[string]string{"file": "PRIVATE_HEADER\n0.1\n0.2\n"}, 1},
	}
	for _, tc := range tests {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, request(t, tc.path, tc.opts, tc.files))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var r tabular.Result
		if json.Unmarshal(w.Body.Bytes(), &r) != nil || r.OutputRows != tc.wantRows {
			t.Fatal(w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Prototype") != "local-unpaid" {
			t.Fatal(w.Header())
		}
	}
	entries, e := os.ReadDir(area)
	if e != nil || len(entries) != 0 {
		t.Fatal("customer data spilled to disk")
	}
	for _, canary := range []string{"PRIVATE_", "private-filename", "127.0.0.1", "key_columns", "columns", "rows"} {
		if strings.Contains(logs.String(), canary) {
			t.Fatal("customer data in logs")
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var v map[string]any
		if json.Unmarshal([]byte(line), &v) != nil {
			t.Fatal(line)
		}
		if len(v) != 7 {
			t.Fatal("unexpected log field", v)
		}
		for k := range v {
			if !map[string]bool{"time": true, "level": true, "msg": true, "operation": true, "status": true, "code": true, "duration_bucket": true}[k] {
				t.Fatal(k)
			}
		}
	}
}

func TestRejectedInputsAndPrivacySafeErrors(t *testing.T) {
	s := New(direct, nil)
	valid := `{"key_columns":["id"],"keep":"first"}`
	for _, tc := range []struct {
		path, opts string
		files      map[string]string
		status     int
		code       string
	}{
		{"/csv/dedupe", valid, map[string]string{"left": "id\nx\n"}, 400, "invalid_parts"},
		{"/csv/dedupe", `{"key_columns":["PRIVATE_COL"],"keep":"first"}`, map[string]string{"file": "id\nx\n"}, 422, "invalid_columns"},
		{"/csv/dedupe", `{"key_columns":["id"],"keep":"first","instruction":"PRIVATE_INSTRUCTION"}`, map[string]string{"file": "id\nx\n"}, 400, "invalid_options"},
		{"/csv/dedupe?PRIVATE_TOKEN=1", valid, map[string]string{"file": "id\nx\n"}, 400, "noncanonical_url"},
		{"/private-path", valid, map[string]string{"file": "id\nx\n"}, 404, "not_found"},
		{"/csv/dedupe", valid, map[string]string{"file": "id\n\"PRIVATE_BAD_VALUE"}, 400, "invalid_csv"},
		{"/csv/dedupe", strings.Repeat("x", tabular.MaxOptions+1), map[string]string{"file": "id\nx\n"}, 413, "options_limit"},
	} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, request(t, tc.path, tc.opts, tc.files))
		var result map[string]string
		json.Unmarshal(w.Body.Bytes(), &result)
		if w.Code != tc.status || result["error"] != tc.code || strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, content := range []string{"application/json", "text/csv", "multipart/form-data"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:18082/csv/dedupe", strings.NewReader("PRIVATE_BODY"))
		r.Header.Set("Content-Type", content)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 415 {
			t.Fatal(w.Code)
		}
	}
}

func TestDuplicatePartsTransferEncodingsAndCrossOriginAreRejected(t *testing.T) {
	s := New(direct, nil)
	for _, duplicate := range []bool{false, true} {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		p, _ := mw.CreateFormField("options")
		io.WriteString(p, `{"key_columns":["id"],"keep":"first"}`)
		p, _ = mw.CreateFormField("file")
		io.WriteString(p, "id\nx\n")
		if duplicate {
			p, _ = mw.CreateFormField("options")
			io.WriteString(p, `{}`)
		}
		mw.Close()
		r := httptest.NewRequest("POST", "http://127.0.0.1:18082/csv/dedupe", &b)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		if !duplicate {
			r.Header.Set("Origin", "https://attacker.example")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if duplicate && w.Code != 400 || !duplicate && w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	// The raw multipart API must reject quoted-printable rather than silently decode.
	body := "--b\r\nContent-Disposition: form-data; name=\"options\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}\r\n--b--\r\n"
	r := httptest.NewRequest("POST", "http://127.0.0.1:18082/csv/dedupe", strings.NewReader(body))
	r.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestOneAdmissionAndCancellation(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	s := New(func(ctx context.Context, j Job) (tabular.Result, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return tabular.Result{}, &tabular.Error{Code: "request_cancelled", Status: 408}
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := request(t, "/csv/dedupe", `{"key_columns":["id"],"keep":"first"}`, map[string]string{"file": "id\nx\n"}).WithContext(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.ServeHTTP(httptest.NewRecorder(), first) }()
	<-entered
	w := httptest.NewRecorder()
	s.ServeHTTP(w, request(t, "/csv/dedupe", `{"key_columns":["id"],"keep":"first"}`, map[string]string{"file": "id\nx\n"}))
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release admission")
	}
}

func TestRequestCapBeforeWorkerAndNoPartialResult(t *testing.T) {
	called := false
	s := New(func(context.Context, Job) (tabular.Result, error) { called = true; return tabular.Result{}, nil }, nil)
	r := request(t, "/csv/dedupe", `{}`, map[string]string{"file": "id\nx\n"})
	r.ContentLength = MaxRequest + 1
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 413 || called {
		t.Fatal(w.Code, called)
	}
}

func TestWorkerResultShapeAndErrorAllowlist(t *testing.T) {
	r := tabular.Result{Operation: "dedupe", Columns: []string{"id"}, Rows: [][]string{{"x"}}, InputRows: map[string]int{"file": 1}, OutputRows: 1}
	if !validResult("dedupe", r) {
		t.Fatal("valid result refused")
	}
	r.InputRows = map[string]int{"PRIVATE": 1}
	if validResult("dedupe", r) {
		t.Fatal("unknown input accepted")
	}
	if knownError(&tabular.Error{Code: "PRIVATE", Status: 422}) {
		t.Fatal("arbitrary worker diagnostic accepted")
	}
	a := createArgs("sha256:"+strings.Repeat("0", 64), "test", "job")
	for _, want := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65532:65532", "--memory=512m", "--memory-swap=512m", "--cpus=1", "--pids-limit=64", "--log-driver=none"} {
		found := false
		for _, arg := range a {
			found = found || arg == want
		}
		if !found {
			t.Fatal(want)
		}
	}
}
