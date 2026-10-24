//go:build linux && (arm64 || amd64)

// Package transformguard installs a process-wide filter before reading input.
// This is defense in depth, not a claim of arbitrary-code sandbox completeness.
package transformguard

import (
	"runtime"
	"syscall"
	"unsafe"
)

func Install() error { return install(false) }
func install(private bool) error {
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
	if private {
		allowed := []uint32{63, 64, 57, 80, 62, 222, 226, 215, 214, 134, 135, 139, 65, 66, 124, 216, 233, 101, 172, 93, 25, 113, 169, 132, 178, 98, 123, 96, 128, 94, 22, 21, 20, 19, 59, 278, 293, 115, 131, 174, 175, 176, 177, 173}
		if runtime.GOARCH == "amd64" {
			allowed = []uint32{0, 1, 3, 5, 8, 9, 10, 11, 12, 13, 14, 15, 19, 20, 24, 25, 28, 35, 39, 60, 72, 96, 131, 158, 186, 201, 202, 204, 218, 219, 228, 230, 231, 232, 233, 234, 281, 290, 291, 293, 318, 334, 102, 107, 104, 108, 110, 441}
		}
		p = []syscall.SockFilter{stmt(0x20, 4), jump(arch, 1, 0), stmt(0x06, 0x80000000), stmt(0x20, 0), {Code: 0x35, K: 0x40000000, Jf: 1}, stmt(0x06, 0x80000000)}
		p = append(p, jump(435, 0, 1), stmt(0x06, 0x00050000|38))
		// The static Go runtime uses exactly VM|FS|FILES|SIGHAND|SYSVSEM|THREAD.
		// No namespace, signal, parent, tracing, or other clone flags are admitted.
		p = append(p, jump(clone, 0, 7), stmt(0x20, 20), jump(0, 1, 0), stmt(0x06, deny), stmt(0x20, 16), jump(0x50f00, 1, 0), stmt(0x06, deny), stmt(0x06, 0x7fff0000))
		for _, call := range allowed {
			p = append(p, jump(call, 0, 1), stmt(0x06, 0x7fff0000))
		}
		p = append(p, stmt(0x06, deny))
	}
	program := syscall.SockFprog{Len: uint16(len(p)), Filter: &p[0]}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0)
	if e != 0 {
		return e
	}
	// SECCOMP_SET_MODE_FILTER + TSYNC covers every existing Go runtime thread.
	result, _, errno := syscall.RawSyscall(nr, 1, 1, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(p)
	return filterResult(result, errno)
}

func filterResult(result uintptr, errno syscall.Errno) error {
	if errno != 0 {
		return errno
	}
	// TSYNC can return the unsynchronized thread ID without setting errno.
	// No filter was installed in that case; fail closed before reading data.
	if result != 0 {
		return syscall.ESRCH
	}
	return nil
}
