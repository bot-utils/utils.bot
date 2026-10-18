// Command native-test runs the native integration suites without a runtime shell.
// It is copied into the integration-test image only.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	// Deterministic first-worker failures exist only in the integration image.
	// The second worker is always the real production Poppler executable.
	if filepath.Base(os.Args[0]) == "pdfium-worker" {
		switch filepath.Base(filepath.Dir(os.Args[0])) {
		case "document-error":
			os.Exit(1)
		case "empty":
			fmt.Println(`{"pageCount":1,"truncated":false,"pages":[{"index":0,"width":612,"height":792,"text":""}]}`)
		case "invalid-output":
			fmt.Println(`{}`)
		case "timeout":
			time.Sleep(time.Hour)
		case "setup-failed":
			os.Exit(20)
		case "password-required":
			os.Exit(13)
		default:
			os.Exit(20)
		}
		return
	}
	for _, name := range []string{"parser", "server", "supervisor"} {
		cmd := exec.Command("/app/"+name+".test", "-test.v")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, name, err)
			os.Exit(1)
		}
	}
}
