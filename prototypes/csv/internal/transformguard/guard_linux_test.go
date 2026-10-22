//go:build linux && (arm64 || amd64)

package transformguard

import (
	"syscall"
	"testing"
)

func TestFilterResultFailsClosed(t *testing.T) {
	if filterResult(0, 0) != nil {
		t.Fatal("successful installation rejected")
	}
	if filterResult(1234, 0) != syscall.ESRCH {
		t.Fatal("unsynchronized thread accepted")
	}
	if filterResult(^uintptr(0), syscall.EPERM) != syscall.EPERM {
		t.Fatal("kernel error lost")
	}
}
