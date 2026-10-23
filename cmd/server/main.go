package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/csvcloud"
	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
	"pdfservice/internal/server"
	"pdfservice/internal/telemetry"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	harden()
	resource, alias := os.Getenv("RESOURCE_URL"), os.Getenv("PAYMENT_FUNCTION_ARN")
	if resource == "" || alias == "" {
		slog.Error("missing server configuration")
		os.Exit(1)
	}
	cfg, err := awsenv.Load()
	if err != nil {
		slog.Error("AWS configuration unavailable")
		os.Exit(1)
	}
	client := awslambda.NewFromConfig(cfg, func(o *awslambda.Options) { o.RetryMaxAttempts = 1 })
	paymentConfig, err := protocol.NewConfig(os.Getenv("PAYMENT_MODE"), os.Getenv("PAYMENT_PAY_TO"))
	if err != nil {
		slog.Error("payment configuration unavailable")
		os.Exit(1)
	}
	paymentConfig, err = paymentConfig.WithPublicAccess(os.Getenv("PUBLIC_ACCESS"))
	if err != nil {
		slog.Error("invalid access configuration")
		os.Exit(1)
	}
	worker := parser.Parser{Dir: os.Getenv("WORKER_DIR")}
	service := server.NewWithConfig(resource, server.LambdaPay(client, alias), worker.Parse, paymentConfig)
	switch os.Getenv("CSV_PRIVATE_ENABLED") {
	case "", "0":
		if os.Getenv("CSV_PRIVATE_CONFIG") != "" {
			slog.Error("private CSV config requires explicit enable")
			os.Exit(1)
		}
	case "1":
		service.PrivateCSV, err = csvcloud.NewPrivateAWSHTTP([]byte(os.Getenv("CSV_PRIVATE_CONFIG")), cfg)
		if err != nil {
			slog.Error("private CSV configuration invalid")
			os.Exit(1)
		}
	default:
		slog.Error("invalid private CSV setting")
		os.Exit(1)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	httpServer := &http.Server{Addr: ":" + port, Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second, WriteTimeout: 95 * time.Second, IdleTimeout: 130 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(telemetry.HTTPErrorWriter{}, "", 0)}
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		slog.Error("HTTP listener failed")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		service.Draining.Store(true)
		drain, cancel := context.WithTimeout(context.Background(), 95*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(drain)
	}()
	slog.Info("server starting", "port", port, "paymentMode", paymentConfig.Mode())
	go service.LogHealth(ctx)
	if err = httpServer.Serve(server.LimitListener(listener, server.MaxConnections)); err != nil && err != http.ErrServerClosed {
		slog.Error("HTTP server failed")
		os.Exit(1)
	}
}
