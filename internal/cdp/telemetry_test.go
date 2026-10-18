package cdp

import (
	"context"
	"errors"
	"testing"
)

func TestDiagnosticClassificationNeverIncludesProviderText(t *testing.T) {
	for _, tc := range []struct {
		status int
		reason string
		err    error
		want   string
	}{
		{0, "private body", &HTTPFailure{Status: 401, Kind: ErrUnauthorized}, "unauthorized"},
		{402, "payment secret", ErrUnavailable, "billing_required"}, {429, "body", ErrUnavailable, "rate_limited"},
		{503, "body", ErrUnavailable, "upstream_failure"}, {0, "body", context.DeadlineExceeded, "deadline"},
		{200, "body", ErrResponse, "invalid_response"}, {0, "body", errors.New("private credential"), "transport_failure"},
		{400, "insufficient_funds", nil, "insufficient_funds"}, {400, "untrusted provider data", nil, "unknown"},
		{400, "kyt_risk_detected", nil, "risk_rejected"},
		{400, "invalid_exact_evm_payload_authorization_from_address_kyt", nil, "risk_rejected"},
		{400, "invalid_exact_evm_payload_authorization_to_address_kyt", nil, "risk_rejected"},
		{400, "request_blocked_by_location", nil, "request_blocked_by_location"},
	} {
		if got := diagnosticReason(tc.status, tc.reason, tc.err); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}
