// Private synthetic runtime only; no service route or automatic deployment.
package main

import (
	"context"
	"flag"
	"os"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/csvcloud"
	"time"
)

func main() {
	synthetic := flag.Bool("synthetic-run", false, "explicit private synthetic gate")
	flag.Parse()
	raw := []byte(os.Getenv("CSV_BROKER_BOOTSTRAP"))
	_ = os.Unsetenv("CSV_BROKER_BOOTSTRAP")
	if !*synthetic || len(raw) > 8192 || os.Getuid() != 65532 || harden() != nil {
		os.Exit(78)
	}
	b, e := csvcloud.DecodeBroker(raw, time.Now())
	clear(raw)
	if e != nil {
		os.Exit(78)
	}
	cfg, e := awsenv.Load()
	os.Clearenv()
	if e != nil || csvcloud.ProcessSyntheticBroker(context.Background(), b, cfg) != nil {
		os.Exit(78)
	}
}
