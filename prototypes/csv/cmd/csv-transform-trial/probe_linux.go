//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

func runProbe(mode string) bool {
	switch mode {
	case "artifacts":
		_, e := os.Stat("/work/result.csv.gz")
		ok := os.IsNotExist(e)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]bool{"published_absent": ok, "partial_present": exists("/work/result.partial")})
		return ok
	case "wait":
		if os.WriteFile("/work/result.partial", []byte("synthetic_pending"), 0600) != nil {
			return false
		}
		time.Sleep(2 * time.Hour)
		return false
	case "oom":
		if os.WriteFile("/work/result.partial", []byte("synthetic_pending"), 0600) != nil {
			return false
		}
		data := make([]byte, 3<<30)
		for i := range data {
			data[i] = byte(i)
		}
		runtime.KeepAlive(data)
		return false
	case "isolation":
		work, workError := os.Stat("/work")
		checks := map[string]bool{"private_writable_work": workError == nil && work.IsDir() && work.Mode().Perm()&0077 == 0 && os.WriteFile("/work/.probe", []byte("synthetic"), 0600) == nil, "nonroot": os.Getuid() != 0, "credentials_absent": os.Getenv("AWS_ACCESS_KEY_ID") == "" && os.Getenv("AWS_SECRET_ACCESS_KEY") == "" && os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") == "" && os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") == ""}
		for label, family := range map[string]int{"ipv4_socket_denied": syscall.AF_INET, "ipv6_socket_denied": syscall.AF_INET6, "unix_socket_denied": syscall.AF_UNIX} {
			fd, e := syscall.Socket(family, syscall.SOCK_STREAM, 0)
			checks[label] = e == syscall.EPERM
			if fd >= 0 {
				_ = syscall.Close(fd)
			}
		}
		_, _, uring := syscall.RawSyscall(425, 0, 0, 0)
		checks["uring_denied"] = uring == syscall.EPERM
		_, _, pidfd := syscall.RawSyscall(438, 0, 0, 0)
		checks["foreign_fd_denied"] = pidfd == syscall.EPERM
		checks["exec_denied"] = syscall.Exec("/csv-transform-trial", []string{"/csv-transform-trial"}, nil) == syscall.EPERM
		process, e := os.StartProcess("/csv-transform-trial", []string{"/csv-transform-trial"}, &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
		checks["process_spawn_denied"] = e != nil
		if process != nil {
			_ = process.Kill()
			_, _ = process.Wait()
		}
		f, e := os.Create("/forbidden-probe")
		checks["root_readonly"] = e != nil
		if f != nil {
			f.Close()
		}
		for _, ok := range checks {
			if !ok {
				return false
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(checks)
		return true
	}
	return false
}

func peakRSS() int64 {
	var value syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &value) != nil {
		return 0
	}
	return value.Maxrss * 1024
}

func exists(path string) bool { _, e := os.Stat(path); return e == nil }

// Fill only a small private tmpfs, never the task/host's main storage.
func fillPrivateFS(root string) error {
	var fs syscall.Statfs_t
	if e := syscall.Statfs(root, &fs); e != nil {
		return e
	}
	if fs.Type != 0x01021994 || uint64(fs.Blocks)*uint64(fs.Bsize) > 128<<20 {
		return fmt.Errorf("private_small_tmpfs_required")
	}
	f, e := os.OpenFile(root+"/filler", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	block := make([]byte, 64<<10)
	for written := 0; written <= 128<<20; written += len(block) {
		_, e = f.Write(block)
		if errors.Is(e, syscall.ENOSPC) {
			return nil
		}
		if e != nil {
			return e
		}
	}
	return fmt.Errorf("tmpfs_bound_not_reached")
}
func isENOSPC(e error) bool { return errors.Is(e, syscall.ENOSPC) }
