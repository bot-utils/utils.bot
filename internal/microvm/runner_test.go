package microvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	vm "github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms/types"
	"github.com/aws/smithy-go"
)

func TestJobPhaseTimingsAreNumericAndContainNoCustomerData(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	api := &fakeAPI{}
	r := Runner{API: api, Image: testImage, Version: "1.0", transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}
	if _, err := r.Run(context.Background(), []byte(`{"url":"https://private.invalid/?token=customer-canary"}`)); err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(logs.Bytes(), &row); err != nil {
		t.Fatal("expected one summary event", err)
	}
	for _, field := range []string{"launch_ms", "ready_wait_ms", "auth_ms", "worker_ms", "cleanup_ms", "elapsed_ms"} {
		if value, ok := row[field].(float64); !ok || value < 0 {
			t.Fatal("missing numeric phase duration", field, row[field])
		}
	}
	for _, secret := range []string{"customer-canary", "private.invalid", "secret-token", "mvm-job"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("timing summary exposed customer/VM data")
		}
	}
}

const testImage = "arn:aws:lambda:us-east-2:111111111111:microvm-image:agent-pdf-html-probe"

func TestFailureDiagnosticsCannotIncludeUpstreamContent(t *testing.T) {
	for _, code := range []string{"AccessDeniedException", "ValidationException", "https://private.invalid/?secret=canary"} {
		failure := unavailable("launch", &smithy.GenericAPIError{Code: code, Message: "private-content-and-credentials-canary"})
		if !errors.Is(failure, ErrUnavailable) || strings.Contains(failure.Error(), "canary") || strings.Contains(failure.Error(), "https:") {
			t.Fatal("unsafe diagnostic", failure)
		}
		if code == "ValidationException" && failure.Error() != "microvm_unavailable:launch:ValidationException" {
			t.Fatal("useful bounded stage/code omitted")
		}
	}
}

type fakeAPI struct {
	inputs          []*vm.RunMicrovmInput
	terminated      bool
	cleanupErr      bool
	endpoint        string
	tokens          int
	cleanupCanceled bool
	readyFailures   int
	readyReason     string
	terminations    int
}

func (f *fakeAPI) RunMicrovm(_ context.Context, in *vm.RunMicrovmInput, _ ...func(*vm.Options)) (*vm.RunMicrovmOutput, error) {
	f.inputs = append(f.inputs, in)
	f.terminated = false
	endpoint := f.endpoint
	if endpoint == "" {
		endpoint = "worker.lambda-microvm.us-east-2.on.aws"
	}
	state := types.MicrovmStateRunning
	if len(f.inputs) <= f.readyFailures {
		state = types.MicrovmStatePending
	}
	return &vm.RunMicrovmOutput{MicrovmId: aws.String("mvm-job"), Endpoint: aws.String(endpoint), ImageArn: aws.String(testImage), ImageVersion: aws.String("1.0"), State: state}, nil
}
func (f *fakeAPI) GetMicrovm(_ context.Context, _ *vm.GetMicrovmInput, _ ...func(*vm.Options)) (*vm.GetMicrovmOutput, error) {
	state := types.MicrovmStateRunning
	if f.terminated {
		state = types.MicrovmStateTerminated
	}
	if !f.terminated && len(f.inputs) <= f.readyFailures {
		state = types.MicrovmStateTerminated
	}
	return &vm.GetMicrovmOutput{State: state, StateReason: aws.String(f.readyReason)}, nil
}
func (f *fakeAPI) CreateMicrovmAuthToken(_ context.Context, in *vm.CreateMicrovmAuthTokenInput, _ ...func(*vm.Options)) (*vm.CreateMicrovmAuthTokenOutput, error) {
	f.tokens++
	if len(in.AllowedPorts) != 1 || in.AllowedPorts[0].(*types.PortSpecificationMemberPort).Value != 8080 || aws.ToInt32(in.ExpirationInMinutes) != 1 {
		panic("token scope")
	}
	return &vm.CreateMicrovmAuthTokenOutput{AuthToken: map[string]string{"X-aws-proxy-auth": "secret-token"}}, nil
}
func (f *fakeAPI) TerminateMicrovm(ctx context.Context, _ *vm.TerminateMicrovmInput, _ ...func(*vm.Options)) (*vm.TerminateMicrovmOutput, error) {
	f.terminations++
	f.cleanupCanceled = ctx.Err() != nil
	if f.cleanupErr {
		return nil, errors.New("private-service-error")
	}
	f.terminated = true
	return &vm.TerminateMicrovmOutput{}, nil
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDisposableLifetimeCredentialsAndCleanup(t *testing.T) {
	api := &fakeAPI{}
	r := Runner{API: api, Image: testImage, Version: "1.0", transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://worker.lambda-microvm.us-east-2.on.aws/convert" || req.Header.Get("X-aws-proxy-auth") != "secret-token" || req.Header.Get("Authorization") != "" {
			t.Fatal("unexpected worker transport")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	})}
	for range 2 {
		b, e := r.Run(context.Background(), []byte(`{"url":"private-customer-canary"}`))
		if e != nil || len(b) == 0 || !api.terminated {
			t.Fatal("cleanup must finish before result", e)
		}
	}
	if *api.inputs[0].ClientToken == *api.inputs[1].ClientToken {
		t.Fatal("attempts share identity")
	}
	for _, in := range api.inputs {
		if in.ExecutionRoleArn != nil || in.RunHookPayload != nil || aws.ToInt32(in.MaximumDurationInSeconds) != Lifetime || aws.ToInt32(in.IdlePolicy.MaxIdleDurationSeconds) != 60 || aws.ToBool(in.IdlePolicy.AutoResumeEnabled) || aws.ToInt32(in.IdlePolicy.SuspendedDurationSeconds) != 0 || in.ImageVersion == nil {
			t.Fatal("unsafe lifecycle")
		}
		if _, ok := in.Logging.(*types.LoggingMemberDisabled); !ok {
			t.Fatal("worker content logging")
		}
		for _, connector := range in.IngressNetworkConnectors {
			if strings.Contains(connector, "SHELL") {
				t.Fatal("shell ingress")
			}
		}
	}
}
func TestHostileResponseAndCleanupFailures(t *testing.T) {
	for _, body := range []string{"not JSON", string([]byte{0xff}), `{"ok":true,"OK":false}`, strings.Repeat("x", MaxResponse+1), `{} {}`} {
		api := &fakeAPI{}
		r := Runner{API: api, Image: testImage, Version: "1.0", transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		if _, e := r.Run(context.Background(), []byte(`{}`)); e == nil || !api.terminated {
			t.Fatal("hostile response escaped or cleanup missing")
		}
	}
	api := &fakeAPI{cleanupErr: true}
	r := Runner{API: api, Image: testImage, Version: "1.0", transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	if b, e := r.Run(context.Background(), []byte(`{}`)); e == nil || b != nil {
		t.Fatal("result escaped failed cleanup")
	}
}
func TestWorkerEndpointCannotRedirectCredentialsOrContactInternalServices(t *testing.T) {
	for _, host := range []string{"http://worker.lambda-microvm.us-east-2.on.aws", "https://evil.example/", "https://127.0.0.1/", "https://worker.lambda-microvm.us-east-2.on.aws@evil.example/", "https://worker.lambda-microvm.us-east-2.on.aws/?x=1"} {
		api := &fakeAPI{endpoint: host}
		r := Runner{API: api, Image: testImage, Version: "1.0"}
		if _, e := r.Run(context.Background(), []byte(`{}`)); e == nil || api.tokens != 0 || !api.terminated {
			t.Fatal("unsafe endpoint", host)
		}
	}
	api := &fakeAPI{}
	calls := 0
	r := Runner{API: api, Image: testImage, Version: "1.0", transport: roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://evil.example/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if _, e := r.Run(context.Background(), []byte(`{}`)); e == nil || calls != 1 || !api.terminated {
		t.Fatal("redirect followed")
	}
}
func TestCanceledRequestStillTerminatesVM(t *testing.T) {
	api := &fakeAPI{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Runner{API: api, Image: testImage, Version: "1.0", transport: roundTrip(func(*http.Request) (*http.Response, error) { cancel(); return nil, context.Canceled })}
	if _, e := r.Run(ctx, []byte(`{}`)); e == nil || !api.terminated || api.cleanupCanceled {
		t.Fatal("cancellation prevented cleanup")
	}
}

func TestStartupRetryIsBoundedAndRequiresConfirmedUnusedVM(t *testing.T) {
	for _, tc := range []struct {
		name            string
		failures        int
		reason          string
		cleanupErr      bool
		launches, calls int
		wantError       bool
	}{
		{"transient-service-failure", 1, "Internal service error.", false, 2, 1, false},
		{"persistent-service-failure", 3, "Internal service error.", false, 2, 0, true},
		{"unconfirmed-cleanup", 1, "Internal service error.", true, 1, 0, true},
		{"unknown-terminal-reason", 1, "private-source-canary", false, 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeAPI{readyFailures: tc.failures, readyReason: tc.reason, cleanupErr: tc.cleanupErr}
			calls := 0
			r := Runner{API: api, Image: testImage, Version: "1.0", transport: roundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}
			_, err := r.Run(context.Background(), []byte(`{"url":"private-source-canary"}`))
			if (err != nil) != tc.wantError || len(api.inputs) != tc.launches || calls != tc.calls || api.tokens != tc.calls || api.terminations != tc.launches {
				t.Fatalf("unsafe startup retry: launches=%d HTTP=%d tokens=%d terminations=%d error=%v", len(api.inputs), calls, api.tokens, api.terminations, err)
			}
			if len(api.inputs) == 2 && *api.inputs[0].ClientToken == *api.inputs[1].ClientToken {
				t.Fatal("fresh launch reused identity")
			}
		})
	}
}
