//go:build linux && (arm64 || amd64)

package main

import (
	"os"
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

func initSpool() error {
	if os.Getuid() != 0 || guard.CheckCapabilities(1) != nil {
		return syscall.EPERM
	}
	if guard.Install() != nil {
		return syscall.EPERM
	}
	if os.Chmod("/spool", 0700) != nil || os.Chown("/spool", 65532, 65532) != nil {
		return syscall.EPERM
	}
	return nil
}
