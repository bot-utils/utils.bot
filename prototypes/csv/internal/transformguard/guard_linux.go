//go:build linux && (arm64 || amd64)

// Package transformguard installs a process-wide filter before reading input.
// This is defense in depth, not a claim of arbitrary-code sandbox completeness.
package transformguard

import (
	"runtime"
	"syscall"
	"unsafe"
)

func Install() error {
	arch, nr, clone := uint32(0xc00000b7), uintptr(277), uint32(220)
	denied := []uint32{198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 242, 243, 269, 221, 281, 97, 268, 40, 39, 117, 270, 271}
	if runtime.GOARCH == "amd64" {
		arch = 0xc000003e
		nr = 317
		clone = 56
		denied = []uint32{41, 53, 42, 43, 49, 50, 44, 45, 46, 47, 288, 299, 307, 59, 322, 57, 58, 272, 308, 165, 166, 101, 310, 311}
	}
	denied = append(denied, 425, 426, 427, 438) // io_uring socket bypasses and foreign descriptor acquisition
	stmt := func(code uint16, k uint32) syscall.SockFilter { return syscall.SockFilter{Code: code, K: k} }
	jump := func(k uint32, t, f uint8) syscall.SockFilter {
		return syscall.SockFilter{Code: 0x15, K: k, Jt: t, Jf: f}
	}
	const deny = uint32(0x00050000 | uint32(syscall.EPERM))
	p := []syscall.SockFilter{stmt(0x20, 4), jump(arch, 1, 0), stmt(0x06, 0x80000000), stmt(0x20, 0)}
	// Refuse x32 syscall-number aliases as well as unexpected audit architectures.
	p = append(p, syscall.SockFilter{Code: 0x35, K: 0x40000000, Jf: 1}, stmt(0x06, 0x80000000))
	for _, call := range denied {
		p = append(p, jump(call, 0, 1), stmt(0x06, deny))
	}
	// Force unsupported clone3 to fail; only same-process runtime threads may clone.
	p = append(p, jump(435, 0, 1), stmt(0x06, 0x00050000|38))
	p = append(p, jump(clone, 0, 5), stmt(0x20, 16), stmt(0x54, 0x10100), jump(0x10100, 1, 0), stmt(0x06, deny), stmt(0x06, 0x7fff0000), stmt(0x06, 0x7fff0000))
	program := syscall.SockFprog{Len: uint16(len(p)), Filter: &p[0]}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0)
	if e != 0 {
		return e
	}
	// SECCOMP_SET_MODE_FILTER + TSYNC covers every existing Go runtime thread.
	_, _, e = syscall.RawSyscall(nr, 1, 1, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(p)
	if e != 0 {
		return e
	}
	return nil
}
