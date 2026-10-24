// Private synthetic worker only. No service route or automatic deployment.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"pdfservice/internal/csvwire"
	"time"
)

func main() {
	mode := flag.String("mode", "", "explicit private worker mode")
	flag.Parse()
	duration := 90 * time.Second
	if *mode == "fifo-init-stream" || *mode == "parser-stream" || *mode == "transport-stream" {
		duration = 390 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	var e error
	switch *mode {
	case "descriptor-probe":
		e = descriptorProbe()
	case "fifo-init":
		e = initPipes()
	case "fifo-init-stream":
		e = initStreamPipes()
	case "parser-stream":
		e = streamParser(ctx)
	case "parser":
		e = parser(ctx, false)
	case "probe":
		e = parser(ctx, true)
	case "sandbox-stream-stdio":
		e = streamStdio()
	case "sandbox-stdio":
		e = stdio(false)
	case "probe-stdio":
		e = stdio(true)
	case "transport", "transport-stream":
		raw := os.Getenv("CSV_TLS_BOOTSTRAP")
		_ = os.Unsetenv("CSV_TLS_BOOTSTRAP")
		if hardenTransport() != nil {
			e = csvwire.ErrWorker
			break
		}
		cfg, err := csvwire.ServerTLS([]byte(raw), time.Now())
		raw = ""
		if err == nil && ((*mode == "transport-stream") != (cfg.NextProtos[0] == csvwire.StreamProtocol)) {
			err = csvwire.ErrWire
		}
		if err != nil {
			e = err
			break
		}
		var ln net.Listener
		ln, e = net.Listen("tcp4", ":8443")
		if e != nil {
			break
		}
		var in, out *os.File
		in, out, e = openPipes(ctx, false)
		if e != nil {
			ln.Close()
			break
		}
		defer in.Close()
		defer out.Close()
		e = csvwire.ServeOne(ctx, ln, cfg, in, out)
	default:
		os.Exit(2)
	}
	if e != nil {
		os.Exit(78)
	}
}

// The probe emits fixed booleans only. Kernel paths, environment, credentials,
// denied IPs, contents and raw errors never enter its response.
func emitProbe(w *os.File, v map[string]bool) error { return json.NewEncoder(w).Encode(v) }
