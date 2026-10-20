package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestRequestURLPreservesRoutingAndUsefulQueryEvidence(t *testing.T) {
	for _, tc := range []struct{ path, query, want string }{
		{"/v100/words", "", "/v100/words"},
		{"/%761/pdf/text", "format=json&format=xml", "/%761/pdf/text?format=json&format=xml"},
		{"//v1/../pdf/text", "debug=true", "//v1/../pdf/text?debug=true"},
		{"/v1/pdf/text", "unknown=value%2fwith%2Fencoding&empty=&flag", "/v1/pdf/text?unknown=value%2fwith%2Fencoding&empty=&flag"},
	} {
		got, truncated, redacted := RequestURL(tc.path, tc.query, false)
		if got != tc.want || truncated || redacted {
			t.Fatalf("lost routing evidence: %q, %v, %v", got, truncated, redacted)
		}
	}
	if got, _, _ := RequestURL("/health", "", true); got != "/health?" {
		t.Fatal("empty query marker lost", got)
	}
}

func TestRequestURLRedactsRecognizableSensitiveValuesOnly(t *testing.T) {
	for _, key := range []string{"token", "%74oken", "%2574oken", "ACCESS_TOKEN", "api-key", "Password", "x-amz-signature", "payment-signature", "private_key", "wallet-key", "seed_phrase", "mnemonic", "AWSAccessKeyId", "auth", "credentials", "email", "bad%xx"} {
		query := "format=json&" + key + "=private-canary&" + key + "=second-canary&debug=true"
		want := "/v100/words?format=json&" + key + "=[REDACTED]&" + key + "=[REDACTED]&debug=true"
		got, truncated, redacted := RequestURL("/v100/words", query, false)
		if got != want || truncated || !redacted {
			t.Fatal("redaction hid routing evidence or exposed a credential", key, got)
		}
	}
}

func TestRequestURLBoundsUTF8AndMarksTruncation(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", 100000), strings.Repeat("界", 2000), strings.Repeat("😀", 2000), strings.Repeat("\xff", 4000)} {
		target, truncated, _ := RequestURL("/v100/words", "debug="+value, false)
		if !truncated || len(target) > MaxRequestURLBytes || !utf8.ValidString(target) || !strings.HasPrefix(target, "/v100/words?debug=") {
			t.Fatal("unbounded or invalid target")
		}
	}
	got, truncated, redacted := RequestURL("/v100/words", "token="+strings.Repeat("private-canary", 10000), false)
	if got != "/v100/words?token=[REDACTED]" || truncated || !redacted {
		t.Fatal("secret must be redacted before size truncation")
	}
}

func TestRequestURLDiagnosticCannotForgeLogRecords(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	RequestDetailSummary(context.Background(), 404, false, false, false, time.Now(), Request{
		Route: "unsupported", Method: "GET", RequestPath: "/v100/words", RequestQuery: "format=\"\n\r&token=private-canary",
	})
	var record map[string]any
	if bytes.Count(logs.Bytes(), []byte{'\n'}) != 1 || json.Unmarshal(logs.Bytes(), &record) != nil || bytes.Contains(logs.Bytes(), []byte("private-canary")) {
		t.Fatal("unsafe URL log")
	}
	if record["route"] != "unsupported" || record["request_url"] != "/v100/words?format=\"\n\r&token=[REDACTED]" || record["request_url_redacted"] != true {
		t.Fatal("real path or debug evidence lost", record)
	}
}
