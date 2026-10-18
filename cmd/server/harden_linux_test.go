//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestSupervisorHardeningIsAppliedInRealLinuxProcess(t *testing.T) {
	if os.Getenv("PDF_HARDEN_TEST_CHILD") == "1" {
		harden()
		dumpable, _, err := syscall.Syscall6(syscall.SYS_PRCTL, 3, 0, 0, 0, 0, 0) // PR_GET_DUMPABLE
		if err != 0 || dumpable != 0 {
			t.Fatal("supervisor remains dumpable")
		}
		privileges, _, err := syscall.Syscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0) // PR_GET_NO_NEW_PRIVS
		if err != 0 || privileges != 1 {
			t.Fatal("supervisor can gain privileges")
		}
		var limit syscall.Rlimit
		if syscall.Getrlimit(syscall.RLIMIT_CORE, &limit) != nil || limit.Cur != 0 || limit.Max != 0 {
			t.Fatal("core dump limit not locked")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisorHardeningIsAppliedInRealLinuxProcess$")
	cmd.Env = append(os.Environ(), "PDF_HARDEN_TEST_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Linux supervisor check: %v %s", err, out)
	}
}
