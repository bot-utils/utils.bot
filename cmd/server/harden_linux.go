//go:build linux

package main

import (
	"log/slog"
	"os"
	"syscall"
)

func harden() {
	_, _, err := syscall.Syscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0) // PR_SET_DUMPABLE=0
	if err != 0 {
		slog.Error("supervisor confinement failed")
		os.Exit(1)
	}
	_, _, err = syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0) // PR_SET_NO_NEW_PRIVS=1
	if err != 0 {
		slog.Error("supervisor privilege policy failed")
		os.Exit(1)
	}
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}) != nil {
		slog.Error("core policy failed")
		os.Exit(1)
	}
}
