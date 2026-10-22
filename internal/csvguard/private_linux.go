//go:build linux && (arm64 || amd64)

package transformguard

import (
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// InstallPrivate enforces seccomp-no-paths-v1 across all runtime threads before
// input. The static in-memory engine needs only preopened directional pipe I/O.
// Unknown syscalls default to EPERM. This is not the spill-to-disk profile.
func InstallPrivate() error {
	if os.Getuid() != 65533 {
		return errUID
	}
	if !NoCredentials() || CheckCapabilities(0) != nil {
		return errKernel
	}
	os.Clearenv()
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(768 << 20)
	for fd := 0; fd <= 1; fd++ {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
			return errPipe
		}
		flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
		if e != 0 || int(flags)&syscall.O_ACCMODE != []int{syscall.O_RDONLY, syscall.O_WRONLY}[fd] {
			return errPipe
		}
	}
	// Only pipe 0/1 carry data. Stderr is closed; inherited descriptors are closed.
	_ = syscall.Close(2)
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		return errFD
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil || fd < 3 {
			continue
		}
		target, e := os.Readlink("/proc/self/fd/" + entry.Name())
		if e != nil {
			continue
		}
		if target == "anon_inode:[eventpoll]" || target == "anon_inode:[eventfd]" {
			continue
		}
		if syscall.Close(fd) != nil {
			return errFD
		}
	}

	for _, r := range []struct {
		k int
		v uint64
	}{{syscall.RLIMIT_CORE, 0}, {syscall.RLIMIT_NOFILE, 64}} {
		if syscall.Setrlimit(r.k, &syscall.Rlimit{Cur: r.v, Max: r.v}) != nil {
			return errLimit
		}
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 4, 0, 0); e != 0 {
		return errKernel
	}
	// Hold existing OS threads before TSYNC, then verify each after install.
	start, results, ready := make(chan struct{}), make(chan bool, 4), make(chan struct{}, 4)
	for range 4 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-start
			results <- deniedPath()
		}()
	}
	for range 4 {
		<-ready
	}
	if install(true) != nil {
		close(start)
		for range 4 {
			<-results
		}
		return errKernel
	}
	close(start)
	for range 4 {
		if !<-results {
			return errKernel
		}
	}
	return nil
}

// NoCredentials rejects unexpected credential sources rather than hiding them.
func NoCredentials() bool {
	for _, e := range os.Environ() {
		k, v, _ := strings.Cut(e, "=")
		if v != "" && (strings.HasPrefix(k, "AWS_") || k == "CSV_TLS_BOOTSTRAP") {
			return false
		}
	}
	return true
}
func CheckCapabilities(expected uint64) error {
	header := [2]uint32{0x20080522, 0}
	data := [6]uint32{}
	_, _, e := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data)), 0)
	if e != 0 || uint64(data[0])|uint64(data[3])<<32 != expected || uint64(data[1])|uint64(data[4])<<32 != expected || data[2] != 0 || data[5] != 0 {
		return errKernel
	}
	// Ambient set must also be empty; failure to inspect is fail-closed.
	for cap := uintptr(0); cap < 41; cap++ {
		v, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, 47, 1, cap, 0, 0, 0)
		if e != 0 || v != 0 {
			return errKernel
		}
	}
	return nil
}
func deniedPath() bool {
	f, e := os.Open("/proc/self/environ")
	if f != nil {
		f.Close()
	}
	return e != nil && (os.IsPermission(e))
}
