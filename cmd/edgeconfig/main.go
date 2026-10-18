package main

import (
	"flag"
	"fmt"
	"os"

	"pdfservice/internal/edge"
	"pdfservice/internal/protocol"
)

func main() {
	owner := flag.String("owner-ip", "", "owner IPv4 address; edge remains private")
	staticRoute := flag.String("static-route", "", "serve /info, /terms or /discovery without an origin")
	flag.Parse()
	cfg, err := protocol.NewConfig(os.Getenv("PAYMENT_MODE"), os.Getenv("PAYMENT_PAY_TO"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid payment configuration")
		os.Exit(1)
	}
	cfg, err = cfg.WithPublicAccess(os.Getenv("PUBLIC_ACCESS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid access configuration")
		os.Exit(1)
	}
	var code string
	resource := os.Getenv("RESOURCE_URL")
	if resource == "" {
		resource = protocol.SiteOrigin + "/v1/pdf/text"
	}
	if *staticRoute == "" {
		code, err = edge.CodeWithConfig(resource, *owner, cfg)
	} else {
		code, err = edge.StaticCodeForResource(*staticRoute, *owner, cfg, resource)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(code)
}
