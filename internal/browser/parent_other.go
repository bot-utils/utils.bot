//go:build !linux

package browser

func protectParent() error { return ErrBrowser }
