// Credential-free, one-attempt HTTP worker for AWS Lambda MicroVMs.
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"pdfservice/internal/browser"
	"pdfservice/internal/htmlrender"
)

func main() {
	bucket := os.Getenv("THREAT_BUCKET")
	probe := os.Getenv("MICROVM_PROBE") == "1"
	// No build/runtime credential provider is initialized or retained by this
	// application. The worker uses short-lived read links for public threat data.
	os.Clearenv()
	os.Setenv("HOME", "/tmp")
	os.Setenv("PATH", "/usr/bin:/bin")
	if bucket == "" {
		os.Exit(1)
	}
	const launcher = "/opt/utils/browser-launch"
	const chromium = "/usr/lib/chromium/chromium-headless-shell"
	warm := &browser.Warm{Launcher: launcher, Executable: chromium}
	// Initialization keeps a blank Chromium process and its pipes in the image.
	// Validation runs only a synthetic page in a clone, allowing AWS to learn the
	// snapshot working set without snapshotting any page or customer state.
	prepare := func(ctx context.Context) error {
		if err := warm.Prepare(ctx); err != nil {
			return err
		}
		debug.FreeOSMemory()
		return nil
	}

	worker := &htmlrender.VMServer{Probe: probe, Bucket: bucket, SelfTest: prepare, Validate: warm.Validate, Fetch: (htmlrender.BrowserFetcher{Warm: warm}).Fetch}
	server := &http.Server{Addr: ":8080", Handler: worker, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	if server.ListenAndServe() != nil {
		os.Exit(1)
	}
}
