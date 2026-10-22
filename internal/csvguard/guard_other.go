//go:build !linux || (!arm64 && !amd64)

package transformguard

import "errors"

func Install() error { return errors.New("unsupported sandbox platform") }
