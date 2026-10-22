package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMockSigningKeyMustResolveOutsideState(t *testing.T) {
	root, err := os.MkdirTemp("", "utils-flow-key-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := exec.Command("trash", root).Run(); err != nil {
			t.Error("test scratch cleanup failed")
		}
	})
	state := filepath.Join(root, "state")
	if err = os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(state, "mock.key")
	outside := filepath.Join(root, "mock.key")
	for _, path := range []string{inside, outside} {
		if err = os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if outsideState(state, inside) || !outsideState(state, outside) {
		t.Fatal("key placement boundary failed")
	}
	alias := filepath.Join(root, "alias")
	if err = os.Symlink(state, alias); err != nil {
		t.Fatal(err)
	}
	if outsideState(state, filepath.Join(alias, "mock.key")) {
		t.Fatal("aliased internal key accepted")
	}
}
