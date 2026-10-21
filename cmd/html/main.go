package main

import (
	"log"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/htmltool"
	"pdfservice/internal/microvm"
	"pdfservice/internal/protocol"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := awsenv.Load()
	payment, worker, resource := os.Getenv("PAYMENT_FUNCTION_ARN"), os.Getenv("WORKER_FUNCTION_ARN"), os.Getenv("RESOURCE_URL")
	if err != nil || payment == "" || worker == "" && os.Getenv("MICROVM_IMAGE_ARN") == "" || resource == "" {
		log.Fatal("HTML controller configuration unavailable")
	}
	paymentConfig, err := protocol.NewConfig(os.Getenv("PAYMENT_MODE"), os.Getenv("PAYMENT_PAY_TO"))
	if err != nil || os.Getenv("PAYMENT_MODE") == "" {
		log.Fatal("HTML payment configuration unavailable")
	}
	switch os.Getenv("HTML_JAVASCRIPT") {
	case "", "0":
	case "1":
		paymentConfig = paymentConfig.WithHTMLJavaScript(true)
	default:
		log.Fatal("HTML renderer configuration unavailable")
	}
	client := awslambda.NewFromConfig(cfg, func(o *awslambda.Options) { o.RetryMaxAttempts = 1 })
	work := htmltool.WorkerInvoker(client, worker)
	if image := os.Getenv("MICROVM_IMAGE_ARN"); image != "" {
		if worker != "" || !paymentConfig.HTMLJavaScript() || os.Getenv("MICROVM_IMAGE_VERSION") == "" || os.Getenv("THREAT_BUCKET") == "" {
			log.Fatal("HTML worker configuration unavailable")
		}
		api := lambdamicrovms.NewFromConfig(cfg, func(o *lambdamicrovms.Options) { o.RetryMaxAttempts = 2 })
		storage := s3.NewFromConfig(cfg)
		work = htmltool.MicroVMInvoker(microvm.Runner{API: api, Image: image, Version: os.Getenv("MICROVM_IMAGE_VERSION")}, storage, s3.NewPresignClient(storage), os.Getenv("THREAT_BUCKET"))
	}
	lambda.StartHandler(htmltool.Controller{Config: paymentConfig.ForHTML(), Resource: resource, Pay: htmltool.PaymentInvoker(client, payment), Work: work})
}
