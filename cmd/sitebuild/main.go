package main

import (
	"flag"
	"fmt"
	"os"
	"pdfservice/internal/protocol"
	"pdfservice/internal/staticsite"
)

func main() {
	owner := flag.String("owner-ip", "", "owner IPv4; private unless explicit public configuration")
	output := flag.String("output", "build/site", "local generated site bundle, not a server")
	flag.Parse()
	cfg, err := protocol.NewConfig(os.Getenv("PAYMENT_MODE"), os.Getenv("PAYMENT_PAY_TO"))
	if err != nil {
		fail(err)
	}
	cfg, err = cfg.WithPublicAccess(os.Getenv("PUBLIC_ACCESS"))
	if err != nil {
		fail(err)
	}
	b, err := staticsite.Build(os.Getenv("RESOURCE_URL"), *owner, cfg)
	if err != nil {
		fail(err)
	}
	if err = b.Write(*output); err != nil {
		fail(err)
	}
	fmt.Printf("Rendered %d trusted static objects; no API calls or deployment.\n", len(b.Objects))
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
