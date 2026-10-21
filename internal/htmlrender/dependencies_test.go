package htmlrender

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"testing"
)

// The process handling untrusted source pages must not acquire controller,
// payment, credential-provider or cloud-SDK dependencies through shared code.
func TestDisposableWorkerDependencyBoundary(t *testing.T) {
	wire, err := exec.Command("go", "list", "-deps", "-json", "pdfservice/cmd/html-microvm").Output()
	if err != nil {
		t.Fatal("cannot inspect disposable worker dependency graph", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	for {
		var dependency struct {
			ImportPath string
			Standard   bool
		}
		if err := decoder.Decode(&dependency); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if dependency.Standard {
			continue
		}
		switch dependency.ImportPath {
		case "pdfservice/cmd/html-microvm", "pdfservice/internal/htmlrender", "pdfservice/internal/browser", "pdfservice/internal/jsonwire", "pdfservice/internal/htmllimits",
			"golang.org/x/net/html", "golang.org/x/net/html/atom":
		default:
			t.Errorf("unreviewed dependency in credential-free worker: %s", dependency.ImportPath)
		}
	}
}
