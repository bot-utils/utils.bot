package csvcloud

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/aws/smithy-go"
)

// Private operator diagnostics contain fixed classes only. Never emit provider
// messages, request IDs, keys, URLs, credentials, table names or file content.
func privateDependencyFailure(stage string, err error) {
	if os.Getenv("CSV_PRIVATE_ENABLED") != "1" {
		return
	}
	slog.Warn("private_csv_dependency_failure", "stage", stage, "class", privateFailureClass(err))
}
func privateFailureClass(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedException":
			return "access_denied"
		case "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException":
			return "credentials"
		case "ResourceNotFoundException", "NoSuchBucket", "NoSuchKey":
			return "resource_missing"
		case "Throttling", "ThrottlingException", "ProvisionedThroughputExceededException":
			return "throttled"
		}
		return "aws_service"
	}
	var cert x509.UnknownAuthorityError
	if errors.As(err, &cert) {
		return "tls_trust"
	}
	var network net.Error
	if errors.As(err, &network) {
		return "transport"
	}
	if errors.Is(err, ErrIntegrity) {
		return "integrity"
	}
	if errors.Is(err, ErrInvalid) {
		return "invalid_metadata"
	}
	// Classify credential-provider wrappers without emitting any of their text.
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "credential") {
		return "credentials"
	}
	return "unavailable"
}
