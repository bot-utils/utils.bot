//go:build !linux || (!arm64 && !amd64)

package main

import (
	"errors"
	"pdfservice/internal/csvwire"
)

func harden() error { return errors.New("unsupported_private_broker") }

func initSpool() error { return csvwire.ErrWorker }
