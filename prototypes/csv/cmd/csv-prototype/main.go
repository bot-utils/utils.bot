package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"pdfservice/internal/csvtabular"
	"pdfservice/prototypes/csv/internal/api"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		worker()
		return
	}
	if len(os.Args) == 2 && strings.HasPrefix(os.Args[1], "--probe-") {
		probe(os.Args[1])
		return
	}
	address := flag.String("listen", "127.0.0.1:18082", "loopback address")
	image := flag.String("worker-image", "utils-bot-csv-prototype:local", "prebuilt disposable worker image (never pulled)")
	flag.Parse()
	host, _, err := net.SplitHostPort(*address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		log.Fatal("prototype requires a literal loopback listen address")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	handler := api.New((api.Docker{Image: *image}).Run, logger)
	server := &http.Server{Addr: *address, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal("prototype listener unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		drain, cancel := context.WithTimeout(context.Background(), 42*time.Second)
		defer cancel()
		_ = server.Shutdown(drain)
		close(done)
	}()
	logger.Info("CSV prototype ready", "mode", "local-unpaid", "listen", *address)
	if err := server.Serve(&boundedListener{Listener: listener, slots: make(chan struct{}, 8), done: make(chan struct{})}); err != nil && err != http.ErrServerClosed {
		log.Fatal("prototype listener failed")
	}
	if ctx.Err() != nil {
		<-done
	}
}

func worker() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, api.MaxWire+1))
	if err != nil || len(raw) > api.MaxWire {
		reply(api.Reply{Error: &tabular.Error{Code: "invalid_parts", Status: 400}})
		return
	}
	var job api.Job
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&job) != nil {
		reply(api.Reply{Error: &tabular.Error{Code: "invalid_parts", Status: 400}})
		return
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		reply(api.Reply{Error: &tabular.Error{Code: "invalid_parts", Status: 400}})
		return
	}
	result, err := tabular.Execute(job.Operation, job.Options, job.Inputs)
	if err != nil {
		known, ok := err.(*tabular.Error)
		if !ok {
			known = &tabular.Error{Code: "invalid_options", Status: 400}
		}
		reply(api.Reply{Error: known})
		return
	}
	reply(api.Reply{Result: &result})
}
func reply(r api.Reply) { _ = json.NewEncoder(os.Stdout).Encode(r) }

// These local-only integration probes never accept arguments from HTTP requests.
// They verify actual kernel controls rather than trusting requested Docker flags.
func probe(mode string) {
	switch mode {
	case "--probe-isolation":
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		connection, e := (&net.Dialer{}).DialContext(ctx, "tcp", "198.51.100.1:443")
		if connection != nil {
			connection.Close()
		}
		f, writeErr := os.Create("/csv-probe-forbidden")
		if f != nil {
			f.Close()
		}
		memory, _ := os.ReadFile("/sys/fs/cgroup/memory.max")
		shared, sharedErr := os.Create("/dev/shm/csv-probe-forbidden")
		if shared != nil {
			shared.Close()
		}
		cpu, _ := os.ReadFile("/sys/fs/cgroup/cpu.max")
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"network_denied": e != nil, "write_denied": writeErr != nil, "shared_memory_write_denied": sharedErr != nil, "uid": os.Getuid(), "credential_absent": os.Getenv("CSV_PRIVATE_CANARY") == "", "memory_max": strings.TrimSpace(string(memory)), "cpu_max": strings.TrimSpace(string(cpu))})
	case "--probe-memory":
		data := make([]byte, 700<<20)
		for i := range data {
			data[i] = byte(i)
		}
		os.Stdout.Write(data[:1])
		time.Sleep(time.Minute)
	case "--probe-wait":
		time.Sleep(time.Minute)
	default:
		os.Exit(2)
	}
}
