// csv-flow is an explicitly enabled loopback-only synthetic rehearsal. It is
// never linked into the public service and has no real settlement/cloud adapter.
package main

import (
	"context"
	"encoding/hex"
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

	"utils.bot/csvprototype/internal/api"
	"utils.bot/csvprototype/internal/flow"
)

func main() {
	enabled := flag.Bool("enable-synthetic-flow", false, "required local-only, no-funds rehearsal gate")
	state := flag.String("state", "", "existing absolute private 0700 synthetic state directory")
	keyFile := flag.String("mock-key-file", "", "private 0600 file with a 64-hex synthetic key; outside state directory")
	address := flag.String("listen", "127.0.0.1:18083", "literal loopback address")
	image := flag.String("worker-image", "utils-bot-csv-prototype:local", "prebuilt local isolated image")
	flag.Parse()
	if !*enabled {
		log.Fatal("synthetic flow gate is closed")
	}
	host, _, err := net.SplitHostPort(*address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		log.Fatal("literal loopback address required")
	}
	f, err := os.OpenFile(*keyFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		log.Fatal("synthetic key unavailable")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		log.Fatal("private synthetic key required")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		log.Fatal("private synthetic key owner required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 66))
	f.Close()
	key := strings.TrimSpace(string(raw))
	decoded, decodeErr := hex.DecodeString(key)
	if err != nil || decodeErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != key {
		log.Fatal("invalid synthetic key")
	}
	store, err := flow.OpenStore(*state)
	if err != nil {
		log.Fatal("private flow state unavailable")
	}
	defer store.Close()
	provider := &flow.MockProvider{Store: store, Key: key}
	engine, err := flow.New(store, provider, (api.Docker{Image: *image}).Run)
	if err != nil {
		log.Fatal("flow recovery unavailable")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	handler := flow.NewHTTP(engine, true, logger)
	server := &http.Server{Addr: *address, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal("local listener unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	workDone := make(chan struct{})
	go func() {
		defer close(workDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = engine.RunNext(ctx)
			}
		}
	}()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		<-ctx.Done()
		drain, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		_ = server.Shutdown(drain)
	}()
	logger.Info("CSV flow ready", "mode", "local-synthetic-no-funds")
	if err = server.Serve(&boundedListener{Listener: listener, slots: make(chan struct{}, 8), done: make(chan struct{})}); err != nil && err != http.ErrServerClosed {
		stop()
	}
	<-workDone
	<-serverDone
}
