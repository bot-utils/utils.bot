package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateCSVIsOptionalAndBypassesPublicPaymentAndTelemetry(t *testing.T) {
	service := New("https://utils.bot/v1/pdf/text", nil, nil)
	path := "/csv/jobs/" + strings.Repeat("a", 64) + "/download"
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
	if response.Code != 404 {
		t.Fatal("CSV active by default", response.Code)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	calls := 0
	service.PrivateCSV = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(403) })
	request := httptest.NewRequest("GET", path, nil)
	request.Header.Set("X-CSV-Test-Key", "synthetic-sensitive-key")
	response = httptest.NewRecorder()
	service.Handler().ServeHTTP(response, request)
	if response.Code != 403 || calls != 1 {
		t.Fatal("private route missing")
	}
	if logs.Len() != 0 {
		t.Fatal("private path entered public request telemetry")
	}
	response = httptest.NewRecorder()
	service.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/readme", nil))
	if response.Code != 200 || calls != 1 {
		t.Fatal("private route changed public discovery", response.Code)
	}
	logs.Reset()
	service.Draining.Store(true)
	response = httptest.NewRecorder()
	drainRequest := httptest.NewRequest("GET", path, nil)
	drainRequest.Header.Set("X-CSV-Test-Key", "synthetic-sensitive-key")
	service.Handler().ServeHTTP(response, drainRequest)
	if response.Code != 503 || calls != 1 || response.Header().Get("Retry-After") != "1" || !strings.Contains(response.Body.String(), `"error":"draining"`) {
		t.Fatal("private request admitted during drain")
	}
	var event map[string]any
	if json.Unmarshal(logs.Bytes(), &event) != nil || len(event) != 6 || event["msg"] != "private_csv_response" || event["stage"] != "ingress" || event["class"] != "draining" || event["status"] != float64(503) {
		t.Fatal("invalid private drain telemetry schema")
	}
	for key := range event {
		switch key {
		case "time", "level", "msg", "status", "stage", "class":
		default:
			t.Fatal("unexpected telemetry field")
		}
	}
	for _, sensitive := range []string{path, strings.Repeat("a", 64), "synthetic-sensitive-key", "X-CSV-Test-Key"} {
		if strings.Contains(logs.String(), sensitive) {
			t.Fatal("sensitive telemetry")
		}
	}

}
