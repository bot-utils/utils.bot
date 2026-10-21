package htmltool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
)

type LambdaClient interface {
	Invoke(context.Context, *lambda.InvokeInput, ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
}

func invoke(ctx context.Context, client LambdaClient, arn, tenant string, input, output any, max int) error {
	data, err := json.Marshal(input)
	if err != nil {
		return errors.New("invoke_unavailable")
	}
	request := &lambda.InvokeInput{FunctionName: aws.String(arn), InvocationType: types.InvocationTypeRequestResponse, Payload: data}
	if tenant != "" {
		request.TenantId = aws.String(tenant)
	}
	out, err := client.Invoke(ctx, request)
	if err != nil || out == nil || out.StatusCode != 200 || out.FunctionError != nil || jsonwire.Decode(out.Payload, output, max) != nil {
		return errors.New("invoke_unavailable")
	}
	return nil
}
func PaymentInvoker(client LambdaClient, arn string) PayFunc {
	return func(ctx context.Context, r protocol.PaymentRequest) (out protocol.PaymentResponse, err error) {
		err = invoke(ctx, client, arn, "", r, &out, protocol.MaxPaymentPayload)
		return
	}
}
func WorkerInvoker(client LambdaClient, arn string) WorkFunc {
	return func(ctx context.Context, input Input) (out Result, err error) {
		// Each job, including paid retries, gets a new isolation boundary. Never use
		// a caller-provided tenant ID, a wallet, a URL or a stable content hash.
		id := make([]byte, 32)
		if _, err = rand.Read(id); err != nil {
			return
		}
		err = invoke(ctx, client, arn, hex.EncodeToString(id), input, &out, MaxResult)
		return
	}
}
