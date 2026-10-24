package csvcloud

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// Broker startup stages are exposed only as fixed private ECS exit codes.
// They never print bootstrap data, environment, provider text or file contents.
// 80 bootstrap; 81 SDK configuration; 84 metadata read; 85 job binding;
// 86 transport identity; 87 processing. Metadata failures use fixed classes:
// 88 denied, 89 credentials, 90 transport, 91 TLS, 92 missing resource,
// 93 throttling, 94 deadline, 95 other AWS response. Unknown failures stay 82.
type privateBrokerFailure struct {
	code  int
	cause error
}

func (*privateBrokerFailure) Error() string { return "csv_private_broker_failed" }
func (e *privateBrokerFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}
func brokerFailure(code int, cause error) error {
	return &privateBrokerFailure{code: code, cause: cause}
}
func BrokerFailureExitCode(err error) int {
	if err == nil {
		return 0
	}
	var failure *privateBrokerFailure
	if errors.As(err, &failure) && failure != nil {
		if failure.code == 84 {
			return brokerMetadataExitCode(privateFailureClass(failure.cause))
		}
		switch failure.code {
		case 80, 81, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95:
			return failure.code
		}
	}
	return 82
}

func brokerMetadataExitCode(class string) int {
	switch class {
	case "access_denied":
		return 88
	case "credentials":
		return 89
	case "transport":
		return 90
	case "tls_trust":
		return 91
	case "resource_missing":
		return 92
	case "throttled":
		return 93
	case "deadline":
		return 94
	case "aws_service":
		return 95
	default:
		return 84
	}
}

// Observe one initial read before Repository replaces SDK errors with ErrUnknown.
// Retain only an allowlisted class; no provider text or request is retained.
type brokerMetadataObserver struct {
	DynamoAPI
	class string
}

func (o *brokerMetadataObserver) GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	out, err := o.DynamoAPI.GetItem(ctx, in, opts...)
	if err != nil {
		o.class = privateFailureClass(err)
	}
	return out, err
}
