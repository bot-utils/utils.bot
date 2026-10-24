//go:build linux && (arm64 || amd64)

package main

import (
	"context"
	"errors"
	"io"
	"os"
	guard "pdfservice/internal/csvguard"
	"pdfservice/internal/csvwire"
	"runtime"
	"sync"
	"syscall"
	"time"
)

const exchange = "/exchange"

func initPipes() error       { return initPipesMode(false) }
func initStreamPipes() error { return initPipesMode(true) }
func initPipesMode(stream bool) error {
	if os.Getuid() != 0 || !guard.NoCredentials() || guard.CheckCapabilities(1) != nil {
		return csvwire.ErrWorker
	}
	if guard.Install() != nil {
		return csvwire.ErrWorker
	}
	if stream && (os.Chmod("/spool", 0700) != nil || os.Chown("/spool", 65533, 65533) != nil) {
		return csvwire.ErrWorker
	}
	if os.Chmod(exchange, 0711) != nil {
		return csvwire.ErrWorker
	}
	for _, p := range []struct {
		name string
		mode uint32
	}{{"to-parser", 0420}, {"from-parser", 0240}} {
		path := exchange + "/" + p.name
		if syscall.Mkfifo(path, p.mode) != nil || os.Chmod(path, os.FileMode(p.mode)) != nil || os.Chown(path, 65533, 65532) != nil {
			return csvwire.ErrWorker
		}
	}
	return nil
}
func pipe(ctx context.Context, path string, flags int, mode os.FileMode) (*os.File, error) {
	for {
		info, e := os.Lstat(path)
		if e != nil || info.Mode()&os.ModeNamedPipe == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
			return nil, csvwire.ErrWorker
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 65533 || st.Gid != 65532 {
			return nil, csvwire.ErrWorker
		}
		fd, e := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if e == nil {
			f := os.NewFile(uintptr(fd), path)
			return f, nil
		}
		if !errors.Is(e, syscall.ENXIO) {
			return nil, csvwire.ErrWorker
		}
		select {
		case <-ctx.Done():
			return nil, csvwire.ErrWorker
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func openPipes(ctx context.Context, parser bool) (*os.File, *os.File, error) {
	if parser {
		in, e := pipe(ctx, exchange+"/to-parser", syscall.O_RDONLY, 0420)
		if e != nil {
			return nil, nil, e
		}
		out, e := pipe(ctx, exchange+"/from-parser", syscall.O_WRONLY, 0240)
		if e != nil {
			in.Close()
			return nil, nil, e
		}
		return in, out, nil
	}
	in, e := pipe(ctx, exchange+"/to-parser", syscall.O_WRONLY, 0420)
	if e != nil {
		return nil, nil, e
	}
	out, e := pipe(ctx, exchange+"/from-parser", syscall.O_RDONLY, 0240)
	if e != nil {
		in.Close()
		return nil, nil, e
	}
	deadline, _ := ctx.Deadline()
	if in.SetWriteDeadline(deadline) != nil || out.SetReadDeadline(deadline) != nil {
		in.Close()
		out.Close()
		return nil, nil, csvwire.ErrWorker
	}
	return in, out, nil
}
func parser(ctx context.Context, probe bool) error { return parserMode(ctx, probe, false) }
func streamParser(ctx context.Context) error       { return parserMode(ctx, false, true) }
func parserMode(ctx context.Context, probe, stream bool) error {
	if os.Getuid() != 65533 || !guard.NoCredentials() {
		return csvwire.ErrWorker
	}
	in, out, e := openPipes(ctx, true)
	if e != nil {
		return e
	}
	if syscall.Dup3(int(in.Fd()), 0, 0) != nil || syscall.Dup3(int(out.Fd()), 1, 0) != nil {
		return csvwire.ErrWorker
	}
	in.Close()
	out.Close()
	// Rebuild poll-aware wrappers after dup: initial Docker stdin was /dev/null.
	in, out = os.NewFile(0, "csv-input"), os.NewFile(1, "csv-output")
	deadline, _ := ctx.Deadline()
	if in.SetReadDeadline(deadline) != nil || out.SetWriteDeadline(deadline) != nil {
		return csvwire.ErrWorker
	}
	var spool *os.File
	if stream {
		fd, e := syscall.Open("/spool/result.gz", syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if e != nil {
			return csvwire.ErrWorker
		}
		spool = os.NewFile(uintptr(fd), "private-spool")
		defer spool.Close()
		if guard.InstallPrivateSpool(fd) != nil {
			return csvwire.ErrWorker
		}
	} else if guard.InstallPrivate() != nil {
		return csvwire.ErrWorker
	}
	checks := probes()
	for _, ok := range checks {
		if !ok {
			return csvwire.ErrWorker
		}
	}
	if probe {
		return emitProbe(out, checks)
	}
	ready := "RDY1"
	if stream {
		ready = "RDY2"
	}
	if _, e = out.Write([]byte(ready)); e != nil {
		return csvwire.ErrWorker
	}
	if stream {
		return csvwire.ProcessStream(in, out, spool)
	}
	return csvwire.Process(in, out)
}
func probes() map[string]bool {
	checks := map[string]bool{"nonroot": os.Getuid() == 65533, "transport_secret_absent": os.Getenv("CSV_TLS_BOOTSTRAP") == "", "aws_credentials_absent": os.Getenv("AWS_ACCESS_KEY_ID") == "" && os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") == ""}
	for label, af := range map[string]int{"ipv4_socket_denied": syscall.AF_INET, "ipv6_socket_denied": syscall.AF_INET6, "unix_socket_denied": syscall.AF_UNIX} {
		fd, e := syscall.Socket(af, syscall.SOCK_STREAM, 0)
		checks[label] = e == syscall.EPERM
		if fd >= 0 {
			syscall.Close(fd)
		}
	}
	for label, path := range map[string]string{"proc_denied": "/proc/1/environ", "parent_fd_denied": "/proc/1/fd/0", "other_job_denied": "/other-job/canary", "image_key_denied": "/transport.key", "traversal_denied": "/exchange/../transport.key", "opposite_fifo_denied": "/exchange/to-parser"} {
		f, e := os.OpenFile(path, os.O_RDWR, 0)
		checks[label] = errors.Is(e, syscall.EACCES) || errors.Is(e, syscall.EPERM)
		if f != nil {
			f.Close()
		}
	}
	for label, number := range map[string]uintptr{"io_uring_denied": 425, "openat2_denied": 437, "namespace_denied": uintptr(syscall.SYS_UNSHARE), "process_memory_denied": 270} {
		if runtime.GOARCH == "amd64" && label == "process_memory_denied" {
			number = 310
		}
		_, _, e := syscall.RawSyscall(number, 0, 0, 0)
		checks[label] = e == syscall.EPERM
	}
	// clone with no CLONE_THREAD/CLONE_VM must never create a process.
	_, _, forkErr := syscall.RawSyscall(syscall.SYS_CLONE, 0, 0, 0)
	checks["fork_denied"] = forkErr == syscall.EPERM
	_, statErr := os.Stat("/proc/self")
	checks["path_lookup_denied"] = errors.Is(statErr, syscall.EPERM)
	checks["path_mutation_denied"] = errors.Is(os.Truncate("/exchange/to-parser", 0), syscall.EPERM)
	_, _, e := syscall.RawSyscall(438, 0, 0, 0)
	checks["foreign_fd_denied"] = e == syscall.EPERM
	checks["exec_denied"] = syscall.Exec("/csv-private-worker", []string{"/csv-private-worker"}, nil) == syscall.EPERM
	// Force independently scheduled locked OS threads to try a denied path.
	var wg sync.WaitGroup
	var mu sync.Mutex
	all := true
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			f, e := os.Open("/proc/self/environ")
			if f != nil {
				io.Copy(io.Discard, f)
				f.Close()
			}
			mu.Lock()
			all = all && (errors.Is(e, syscall.EACCES) || errors.Is(e, syscall.EPERM))
			mu.Unlock()
		}()
	}
	wg.Wait()
	checks["all_threads_paths_denied"] = all
	return checks
}

func stdio(probe bool) error { return stdioMode(probe, false) }
func streamStdio() error     { return stdioMode(false, true) }
func stdioMode(probe, stream bool) error {
	var spool *os.File
	var setup error
	if stream {
		fd, e := syscall.Open("/spool/result.gz", syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if e != nil {
			return csvwire.ErrWorker
		}
		spool = os.NewFile(uintptr(fd), "private-spool")
		defer spool.Close()
		setup = guard.InstallPrivateSpool(fd)
	} else {
		setup = guard.InstallPrivate()
	}
	if e := setup; e != nil {
		if probe {
			_ = emitProbe(os.Stdout, map[string]bool{guard.SetupReason(e): true, "sandbox_installed": false})
		}
		return csvwire.ErrWorker
	}
	checks := probes()
	for _, ok := range checks {
		if !ok {
			return csvwire.ErrWorker
		}
	}
	if probe {
		return emitProbe(os.Stdout, checks)
	}
	if stream {
		return csvwire.ProcessStream(os.Stdin, os.Stdout, spool)
	}
	return csvwire.Process(os.Stdin, os.Stdout)
}
func hardenTransport() error {
	if os.Getuid() != 65532 || !guard.NoCredentials() || guard.CheckCapabilities(0) != nil {
		return csvwire.ErrWorker
	}
	os.Clearenv()
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 4, 0, 0); e != 0 {
		return csvwire.ErrWorker
	}
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}) != nil {
		return csvwire.ErrWorker
	}
	return nil
}

func descriptorProbe() error {
	v := map[string]bool{"expected_uid": os.Getuid() == 65533}
	for fd, label := range []string{"input", "output"} {
		var st syscall.Stat_t
		e := syscall.Fstat(fd, &st)
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
		v[label+"_fifo"] = e == nil && st.Mode&syscall.S_IFMT == syscall.S_IFIFO
		v[label+"_direction"] = errno == 0 && int(flags)&syscall.O_ACCMODE == []int{syscall.O_RDONLY, syscall.O_WRONLY}[fd]
	}
	return emitProbe(os.Stdout, v)
}
