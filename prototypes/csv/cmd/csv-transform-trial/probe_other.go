//go:build !linux

package main

import "fmt"

func runProbe(string) bool { return false }

func peakRSS() int64 { return 0 }

func fillPrivateFS(string) error { return fmt.Errorf("unsupported_tmpfs") }
func isENOSPC(error) bool        { return false }
