package cdp

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const ParameterRegion = "us-east-1"

var parameterNames = []string{"/pdf/coinbaseAPIKey", "/pdf/coinbaseAPISecret", "/pdf/receiveAddress"}
var ErrParameters = errors.New("Coinbase parameter configuration unavailable")

type parameterAPI interface {
	GetParameters(context.Context, *ssm.GetParametersInput, ...func(*ssm.Options)) (*ssm.GetParametersOutput, error)
}

func FromParameters(ctx context.Context, api parameterAPI) (*Client, error) {
	out, err := api.GetParameters(ctx, &ssm.GetParametersInput{Names: append([]string(nil), parameterNames...), WithDecryption: aws.Bool(true)})
	if err != nil || out == nil || len(out.InvalidParameters) != 0 || len(out.Parameters) != 3 {
		return nil, ErrParameters
	}
	values := make(map[string]string, 3)
	for _, p := range out.Parameters {
		name := aws.ToString(p.Name)
		value := aws.ToString(p.Value)
		if p.Type != types.ParameterTypeSecureString || value == "" || len(value) > 4096 || values[name] != "" {
			return nil, ErrParameters
		}
		found := false
		for _, n := range parameterNames {
			found = found || name == n
		}
		if !found {
			return nil, ErrParameters
		}
		values[name] = value
	}
	return newClient(values[parameterNames[0]], values[parameterNames[1]], values[parameterNames[2]])
}
