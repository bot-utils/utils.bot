//go:build !linux || (!arm64 && !amd64)

package main

import (
	"context"
	"os"
	"pdfservice/internal/csvwire"
)

func initPipes() error                                            { return csvwire.ErrWorker }
func parser(context.Context, bool) error                          { return csvwire.ErrWorker }
func openPipes(context.Context, bool) (*os.File, *os.File, error) { return nil, nil, csvwire.ErrWorker }

func stdio(bool) error       { return csvwire.ErrWorker }
func hardenTransport() error { return csvwire.ErrWorker }

func descriptorProbe() error { return csvwire.ErrWorker }
