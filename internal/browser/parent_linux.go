package browser

import "syscall"

// Prevent the less-trusted browser from reading the broker's /proc/PID/environ,
// memory and inherited Lambda credentials through same-UID process inspection.
func protectParent() error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0) // PR_SET_DUMPABLE=0
	if errno != 0 {
		return ErrBrowser
	}
	return nil
}
