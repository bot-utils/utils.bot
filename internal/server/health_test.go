package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"
)

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
		if json.Unmarshal(line, &m) != nil || m["msg"] != "process health" || m["status"] != "ready" || m["active_requests"] != float64(0) || len(m) != 7 {
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
