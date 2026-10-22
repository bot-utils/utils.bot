//go:build !linux || (!arm64 && !amd64)

package transformguard

func InstallPrivate() error { return ErrPrivate }
