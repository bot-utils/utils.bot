package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func privateRoot(t *testing.T) string {
	t.Helper()
	root, e := os.MkdirTemp("", "utils-transform-oracle-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := exec.Command("trash", root).Run(); e != nil {
			t.Error(e)
		}
	})
	return root
}
func TestTrialGoldenBytesAndAtomicPublication(t *testing.T) {
	expected := map[string]string{"trim": "fb6b10b2c5cb361ff34d32115cb361c6c41f94ad4fed1201078ddebda5502cd8", "lower": "c9d1a51163d703c0bf3d2553452889b80483512d7ce4695cc34a9b654496cd25", "upper": "0a652a7ab47647a6b7ebc967a454a6b9720ab93c5eb7775c1dadc815be0eb1b6", "replace": "2035166342b2318ef3cf449df68150362e2083143dc332b0ab29fc88778eb4d3"}
	for op, hash := range expected {
		root := privateRoot(t)
		result, e := trial(root, op, 1, "baseline")
		if e != nil || result.LogicalHash != hash || result.Rows != 1072 || result.InputBytes != 1047860 {
			t.Fatal(result, e)
		}
		if _, e = os.Stat(filepath.Join(root, "result.csv.gz")); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Stat(filepath.Join(root, "result.partial")); !os.IsNotExist(e) {
			t.Fatal("partial file survived publication")
		}
	}
	for _, scenario := range []string{"late-expansion", "output-limit", "write-failure", "enospc-injected"} {
		root := privateRoot(t)
		result, e := trial(root, "replace", 1, scenario)
		if e == nil || result.Status != "" {
			t.Fatal("failed trial returned metrics", result, e)
		}
		if _, e = os.Stat(filepath.Join(root, "result.csv.gz")); !os.IsNotExist(e) {
			t.Fatal("failed trial published output")
		}
	}
}
