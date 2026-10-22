//go:build !linux || (!arm64 && !amd64)

package main

import "errors"

func harden() error { return errors.New("unsupported_private_broker") }
