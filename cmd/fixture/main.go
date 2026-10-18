// fixture uses the official x402 EVM client to create testnet payment headers.
// Its public test private key must NEVER be funded or used as a real wallet.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	x402 "github.com/x402-foundation/x402/go/v2"
	exact "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"pdfservice/internal/protocol"
)

func main() {
	resource := flag.String("url", "http://localhost:8080/v1/pdf/text", "canonical resource URL")
	size := flag.Int64("bytes", 0, "PDF byte count for selecting the mock price tier")
	flag.Parse()
	if *size < 0 || *size > protocol.MaxPDF {
		fmt.Fprintln(os.Stderr, "fixture size must be between zero and 100 MiB")
		os.Exit(1)
	}
	cfg := (protocol.Config{}).ForSize(*size)
	// Intentionally public, test-only key. No RPC is used by this tool.
	s, err := signer.NewClientSignerFromPrivateKey("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		panic(err)
	}
	p, err := x402.Newx402Client().Register(protocol.Network, exact.NewExactEvmScheme(s, nil)).CreatePaymentPayload(context.Background(), cfg.Requirements(), cfg.Quote(*resource).Resource, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture signing failed")
		os.Exit(1)
	}
	p.Resource = cfg.Quote(*resource).Resource
	header, err := protocol.Header(p)
	if err != nil {
		panic(err)
	}
	if flag.NArg() > 0 && flag.Arg(0) == "json" {
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Println(header)
}
