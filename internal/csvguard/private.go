package transformguard

import "errors"

const PrivateProfile = "seccomp-no-paths-v1"

var ErrPrivate = errors.New("csv_private_sandbox_unavailable")
var errUID = errors.New("csv_private_uid")
var errPipe = errors.New("csv_private_pipe")
var errFD = errors.New("csv_private_fd")
var errLimit = errors.New("csv_private_limit")
var errKernel = errors.New("csv_private_kernel")

// SetupReason exposes only a fixed classification, never kernel diagnostics.
func SetupReason(e error) string {
	switch e {
	case errUID:
		return "uid"
	case errPipe:
		return "pipe_descriptor"
	case errFD:
		return "ambient_descriptor"
	case errLimit:
		return "resource_limit"
	case errKernel:
		return "kernel_filter"
	default:
		return "unsupported"
	}
}
