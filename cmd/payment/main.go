package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/cdp"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
)

type paymentService interface {
	Handle(context.Context, protocol.PaymentRequest) protocol.PaymentResponse
}

type paymentHandler struct {
	service paymentService
	html    paymentService
}

func (h paymentHandler) Handle(ctx context.Context, r protocol.PaymentRequest) protocol.PaymentResponse {
	switch r.Tool {
	case "":
		return h.service.Handle(ctx, r)
	case "html":
		if h.html != nil {
			return h.html.Handle(ctx, r)
		}
	}
	return protocol.PaymentResponse{Status: 400, Error: "invalid_payment_operation"}
}

func handler(service paymentService) lambda.Handler { return paymentHandler{service: service} }

var paymentRequestFields = map[string]bool{
	"tool": true, "traceID": true, "verifyOnly": true, "checkDocument": true, "documentFailed": true,
	"recordOutcome": true, "header": true, "bodySHA256": true, "bodyLength": true, "deadline": true,
}

func decodePaymentRequest(payload []byte, request *protocol.PaymentRequest) bool {
	if jsonwire.Decode(payload, request, protocol.MaxPaymentPayload) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil {
		return false
	}
	for name := range fields {
		if !paymentRequestFields[name] {
			return false
		}
	}
	return true
}

func (h paymentHandler) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	var request protocol.PaymentRequest
	trimmed := bytes.TrimSpace(payload)
	response := protocol.PaymentResponse{}
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || !decodePaymentRequest(payload, &request) {
		response = protocol.PaymentResponse{Status: 400, Error: "invalid_payment_request"}
	} else {
		// Payment rejection is response data, not a Lambda invocation failure.
		response = h.Handle(ctx, request)
	}
	return json.Marshal(response)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	paymentConfig, err := protocol.NewConfig(os.Getenv("PAYMENT_MODE"), os.Getenv("PAYMENT_PAY_TO"))
	if err != nil || os.Getenv("PAYMENT_MODE") == "" {
		log.Fatal("payment configuration unavailable")
	}
	cfg, err := awsenv.Load()
	if err != nil {
		log.Fatal("AWS configuration unavailable")
	}
	var client *cdp.Client
	if paymentConfig.Mode() != protocol.ModeMock || os.Getenv("CDP_AUTH_CHECK") == "1" {
		if cfg.BaseEndpoint != nil {
			log.Fatal("Coinbase credentials cannot use a local AWS endpoint")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
		client, err = cdp.FromParameters(ctx, ssm.NewFromConfig(cfg, func(o *ssm.Options) { o.Region = cdp.ParameterRegion }))
		if err == nil && paymentConfig.Mode() == protocol.ModeMock {
			var support cdp.Support
			support, err = client.Check(ctx)
			if err == nil {
				log.Printf("coinbase_configuration_checked base=%t base_sepolia=%t settlement_enabled=false", support.Base, support.BaseSepolia)
			}
		}
		cancel()
		if err != nil {
			log.Fatal("Coinbase configuration unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	facilitator, err := configuredFacilitator(ctx, paymentConfig, client)
	cancel()
	if err != nil {
		log.Fatal("payment provider configuration unavailable")
	}
	log.Printf("payment_configuration_ready mode=%s", paymentConfig.Mode())
	table, resource := os.Getenv("PAYMENT_TABLE"), os.Getenv("RESOURCE_URL")
	if table == "" || resource == "" {
		log.Fatal("missing payment configuration")
	}
	service := payment.Service{Store: payment.DynamoStore{Client: dynamodb.NewFromConfig(cfg), Table: table}, Facilitator: facilitator, Resource: resource, Config: paymentConfig}
	h := paymentHandler{service: service}
	if resource := os.Getenv("HTML_RESOURCE_URL"); resource != "" {
		htmlConfig := paymentConfig.ForHTML()
		var htmlProvider payment.Facilitator = payment.MockFacilitator{}
		if htmlConfig.Mode() != protocol.ModeMock {
			htmlProvider, err = client.ForPayments(htmlConfig)
			if err != nil {
				log.Fatal("HTML payment configuration unavailable")
			}
		}
		h.html = payment.Service{Store: service.Store, Facilitator: htmlProvider, Resource: resource, Config: htmlConfig}
	}
	lambda.StartHandler(h)
}
