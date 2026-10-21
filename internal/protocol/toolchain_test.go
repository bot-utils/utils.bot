package protocol

import (
	"os"
	"strings"
	"testing"
)

// GO-2026-6809 affects TLS certificate verification. Keep module selection and
// the independently pinned production builder on the same repaired toolchain.
func TestProductionToolchainIncludesCertificateDistrustFix(t *testing.T) {
	for _, file := range []string{"../../go.mod", "../../infra/go.mod"} {
		b, err := os.ReadFile(file)
		if err != nil || !strings.Contains(string(b), "go 1.26.10\n") {
			t.Fatal("minimum patched Go toolchain missing", file, err)
		}
	}
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil || !strings.HasPrefix(string(b), "FROM golang:1.26.10-bookworm@sha256:") {
		t.Fatal("production builder can reintroduce vulnerable standard library", err)
	}
}
