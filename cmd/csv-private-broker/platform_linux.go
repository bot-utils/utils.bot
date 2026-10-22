//go:build linux && (arm64 || amd64)

package main

import (
	guard "pdfservice/internal/csvguard"
	"syscall"
)

func harden() error {
	if guard.CheckCapabilities(0) != nil {
		return syscall.EPERM
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 4, 0, 0); e != 0 {
		return e
	}
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}
