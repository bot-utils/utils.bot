package csvcloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

func TestPrivateDependencyDiagnosticsNeverLogProviderText(t *testing.T) {
	secret := "private-secret https://example.invalid/signed?token=secret"
	var out bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	defer slog.SetDefault(old)
	t.Setenv("CSV_PRIVATE_ENABLED", "1")
	privateDependencyFailure("dynamodb_get", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: secret})
	privateDependencyFailure("admission_read", errors.New(secret))
	privateDependencyFailure(secret, errors.New(secret))
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "signed?") || !strings.Contains(out.String(), "access_denied") || !strings.Contains(out.String(), `"stage":"unknown"`) {
		t.Fatal("unsafe or missing diagnostic class")
	}
	out.Reset()
	t.Setenv("CSV_PRIVATE_ENABLED", "0")
	privateDependencyFailure("dynamodb_get", errors.New(secret))
	if out.Len() != 0 {
		t.Fatal("private diagnostics enabled outside private mode")
	}
}

func TestPrivateFailureResponseTelemetryHasOnlyFixedFields(t *testing.T) {
	var out bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	defer slog.SetDefault(old)
	secret := "/csv/jobs/" + strings.Repeat("a", 64) + "?token=secret X-CSV-Test-Key credential-secret"
	response := httptest.NewRecorder()
	privateError(response, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: secret})
	var event map[string]any
	if response.Code != 503 || json.Unmarshal(out.Bytes(), &event) != nil || len(event) != 6 || event["msg"] != "private_csv_response" || event["status"] != float64(503) || event["stage"] != "response" || event["class"] != "access_denied" {
		t.Fatal("invalid failure telemetry schema")
	}
	for key := range event {
		switch key {
		case "time", "level", "msg", "status", "stage", "class":
		default:
			t.Fatal("unexpected telemetry field")
		}
	}
	for _, value := range []string{secret, "/csv/", strings.Repeat("a", 64), "token=", "X-CSV-Test-Key", "credential-secret"} {
		if strings.Contains(out.String(), value) {
			t.Fatal("sensitive telemetry")
		}
	}
	out.Reset()
	privateError(httptest.NewRecorder(), ErrInvalid)
	if out.Len() != 0 {
		t.Fatal("expected only server-failure telemetry")
	}
}
