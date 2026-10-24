package csvcloud

import (
	"bytes"
	"errors"
	"log/slog"
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
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "signed?") || !strings.Contains(out.String(), "access_denied") {
		t.Fatal("unsafe or missing diagnostic class")
	}
	out.Reset()
	t.Setenv("CSV_PRIVATE_ENABLED", "0")
	privateDependencyFailure("dynamodb_get", errors.New(secret))
	if out.Len() != 0 {
		t.Fatal("private diagnostics enabled outside private mode")
	}
}
