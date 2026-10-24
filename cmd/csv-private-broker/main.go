// Private synthetic runtime only; no service route or automatic deployment.
package main

import (
	"context"
	"flag"
	"os"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/csvcloud"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// The private executable returns fixed stages only; no error/secret is printed.
type brokerRuntime struct {
	harden, initSpool func() error
	load              func() (aws.Config, error)
	process           func(context.Context, csvcloud.BrokerBootstrap, aws.Config) error
	clearEnvironment  func()
	now               func() time.Time
}

func runBroker(spool, synthetic bool, uid int, raw []byte, runtime brokerRuntime) int {
	defer clear(raw)
	if spool {
		runtime.clearEnvironment()
		if runtime.initSpool() != nil {
			return 83
		}
		return 0
	}
	if !synthetic || len(raw) > 8192 || uid != 65532 {
		return 78
	}
	if runtime.harden() != nil {
		return 79
	}
	b, e := csvcloud.DecodeBroker(raw, runtime.now())
	clear(raw)
	if e != nil {
		return 80
	}
	cfg, e := runtime.load()
	runtime.clearEnvironment()
	if e != nil {
		return 81
	}
	return csvcloud.BrokerFailureExitCode(runtime.process(context.Background(), b, cfg))
}

func main() {
	initSpoolFlag := flag.Bool("init-spool", false, "initialize isolated staging volume")
	synthetic := flag.Bool("synthetic-run", false, "explicit private synthetic gate")
	flag.Parse()
	runtime := brokerRuntime{harden: harden, initSpool: initSpool, load: awsenv.Load, process: csvcloud.ProcessSyntheticBroker, clearEnvironment: os.Clearenv, now: time.Now}
	if *initSpoolFlag {
		os.Exit(runBroker(true, false, os.Getuid(), nil, runtime))
	}
	raw := []byte(os.Getenv("CSV_BROKER_BOOTSTRAP"))
	_ = os.Unsetenv("CSV_BROKER_BOOTSTRAP")
	os.Exit(runBroker(false, *synthetic, os.Getuid(), raw, runtime))
}
