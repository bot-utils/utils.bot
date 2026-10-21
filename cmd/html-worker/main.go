package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/htmltool"
)

func main() {
	cfg, err := awsenv.Load()
	bucket := os.Getenv("THREAT_BUCKET")
	if err != nil || bucket == "" {
		log.Fatal("HTML worker configuration unavailable")
	}
	client := s3.NewFromConfig(cfg)
	lambda.StartHandler(htmltool.Worker{Load: func(ctx context.Context) (htmltool.DomainCheck, error) {
		return htmltool.LoadSnapshot(ctx, client, bucket, time.Now())
	}})
}
