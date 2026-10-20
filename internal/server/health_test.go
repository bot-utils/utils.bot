package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
)

func TestHealthNeverInvokesPaymentOrParsingEvenWhenBusyOrDraining(t *testing.T) {
	payments, parses := 0, 0
	s := New("https://api.utils.bot/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		payments++
		return protocol.PaymentResponse{}, nil
	}, func(context.Context, []byte) (parser.Result, error) {
		parses++
		return parser.Result{}, nil
	})
	s.Slots <- struct{}{}
	for _, draining := range []bool{false, true} {
		s.Draining.Store(draining)
		for _, method := range []string{"GET", "HEAD"} {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest(method, "/health", nil))
			want := 200
			if draining {
				want = 503
			}
			if w.Code != want || payments != 0 || parses != 0 || len(s.Slots) != 1 {
				t.Fatal("health check entered paid processing or changed admission capacity")
			}
		}
	}
}

func TestFrequentHealthProbesAreSilentButRejectedRequestsAreLogged(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	s := New("https://api.utils.bot/v1/pdf/text", nil, nil)
	h := s.Handler()
	for range 1000 {
		for _, method := range []string{"GET", "HEAD"} {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/health", nil))
		}
	}
	if logs.Len() != 0 {
		t.Fatal("health probes flooded logs")
	}
	for _, test := range []struct {
		method, path string
		status       int
	}{{"PUT", "/v1/pdf/text", 405}, {"GET", "/private-canary", 404}, {"POST", "/v1/pdf/text", 402}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
		if w.Code != test.status {
			t.Fatal(w.Code)
		}
	}
	lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))
	if len(lines) != 3 || bytes.Contains(logs.Bytes(), []byte("private-canary")) {
		t.Fatalf("incorrect request logging: %s", logs.Bytes())
	}
}

func TestHealthSummaryOnlyOnFiveMinuteTicksAndStops(t *testing.T) {
	if HealthLogInterval != 5*time.Minute {
		t.Fatal("health interval changed")
	}
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	s := New("https://api.utils.bot/v1/pdf/text", nil, nil)
	ticks := make(chan time.Time, 3)
	for i := 1; i <= 3; i++ {
		ticks <- time.Unix(int64(i)*300, 0)
	}
	close(ticks)
	s.healthLogs(context.Background(), ticks)
	lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("health count=%d", len(lines))
	}
	for _, line := range lines {
		var m map[string]any
		if json.Unmarshal(line, &m) != nil || m["route"] != "/health" || m["requests_since_previous_health"] != float64(0) || m["msg"] != "process health" || m["status"] != "ready" || m["active_requests"] != float64(0) || len(m) != 9 {
			t.Fatalf("health fields: %s", line)
		}
	}
	logs.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ticks = make(chan time.Time, 1)
	ticks <- time.Now()
	s.healthLogs(ctx, ticks)
	if logs.Len() != 0 {
		t.Fatal("cancelled process emitted health record")
	}
	s.Draining.Store(true)
	ticks = make(chan time.Time, 1)
	ticks <- time.Now()
	close(ticks)
	s.healthLogs(context.Background(), ticks)
	if !bytes.Contains(logs.Bytes(), []byte(`"status":"draining"`)) {
		t.Fatal("draining health not reported")
	}
}

func TestRejectedURLIsLoggedWithoutHeadersOrIdentity(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	s := New("https://api.utils.bot/v1/pdf/text", nil, nil)
	r := httptest.NewRequest("POST", "/v1/pdf/text?private-canary=customer-data", nil)
	r.Header.Set("Authorization", "private-authorization")
	r.Header.Set("User-Agent", "private-agent")
	r.RemoteAddr = "198.51.100.42:1111"
	s.Handler().ServeHTTP(httptest.NewRecorder(), r)
	var record map[string]any
	if json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &record) != nil || record["route"] != "/v1/pdf/text" || record["method"] != "POST" || record["status"] != float64(400) {
		t.Fatal(logs.String())
	}
	if record["rejected_url"] != "/v1/pdf/text?private-canary=customer-data" || record["rejected_url_truncated"] != false {
		t.Fatal("rejected path/query missing", record)
	}
	for _, secret := range []string{"private-authorization", "private-agent", "198.51.100.42"} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Fatal("customer data retained", secret)
		}
	}
}

func TestRejectedURLEncodingAndHealthQueryRemainVisible(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	s := New("https://api.utils.bot/v1/pdf/text", nil, nil)
	for _, target := range []string{"/%761/pdf/text", "/v1/pdf/text?", "/health?debug=true"} {
		logs.Reset()
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		var record map[string]any
		if w.Code != 400 || json.Unmarshal(logs.Bytes(), &record) != nil || record["rejected_url"] != target {
			t.Fatal("lost original encoding/query", target, w.Code, logs.String())
		}
	}
}
func TestHealthAccessCountIsAggregatedAndResetWithoutPerProbeLogs(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	s := New("https://api.utils.bot/v1/pdf/text", nil, nil)
	h := s.Handler()
	for range 1000 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/health", nil))
	}
	if logs.Len() != 0 {
		t.Fatal("probe flood")
	}
	ticks := make(chan time.Time, 2)
	ticks <- time.Now()
	ticks <- time.Now()
	close(ticks)
	s.healthLogs(context.Background(), ticks)
	lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatal("unexpected record count")
	}
	for i, line := range lines {
		var r map[string]any
		json.Unmarshal(line, &r)
		want := float64(0)
		if i == 0 {
			want = 1000
		}
		if r["route"] != "/health" || r["requests_since_previous_health"] != want {
			t.Fatal(r)
		}
	}
}

func TestProtectedViewerHealthRequestGetsPrivateAccessRecord(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	s := New("https://api.utils.bot/v1/pdf/text", nil, nil)
	r := httptest.NewRequest("GET", "/health", nil)
	r.Header.Set("X-Agent-Pdf-Origin", "private-origin-canary")
	r.Header.Set("User-Agent", "private-user-canary")
	s.Handler().ServeHTTP(httptest.NewRecorder(), r)
	var record map[string]any
	if json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &record) != nil || record["route"] != "/health" || record["status"] != float64(200) || record["completed"] != float64(0) || record["tool_requests"] != float64(0) {
		t.Fatal(logs.String())
	}
	if bytes.Contains(logs.Bytes(), []byte("canary")) {
		t.Fatal("header leaked")
	}
}
