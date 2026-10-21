package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/htmltool"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := awsenv.Load()
	bucket := os.Getenv("THREAT_BUCKET")
	if err != nil || bucket == "" {
		log.Fatal("Threat updater configuration unavailable")
	}
	client := s3.NewFromConfig(cfg)
	lambda.Start(func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
		defer cancel()
		data, err := htmltool.Refresh(ctx, nil, time.Now())
		if err == nil {
			err = htmltool.SaveSnapshot(ctx, client, bucket, data, time.Now())
		}
		// One fixed summary per scheduled refresh. No domain lists or URLs logged.
		slog.Info("threat_refresh", "success", err == nil)
		if err != nil {
			return htmltool.ErrThreats
		}
		return nil
	})
}
