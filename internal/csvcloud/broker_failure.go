package csvcloud

import "errors"

// Broker startup stages are exposed only as fixed private ECS exit codes.
// They never print bootstrap data, environment, provider text or file contents.
// 80 bootstrap; 81 SDK configuration; 84 metadata read; 85 job binding;
// 86 transport identity; 87 processing. Unknown failures remain generic 82.
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
		switch failure.code {
		case 80, 81, 84, 85, 86, 87:
			return failure.code
		}
	}
	return 82
}
