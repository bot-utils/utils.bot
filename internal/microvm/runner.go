// Package microvm runs a single credential-free disposable worker per request.
package microvm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	vm "github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms/types"
	"github.com/aws/smithy-go"

	"pdfservice/internal/htmllimits"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/telemetry"
)

const MaxJob = htmllimits.VMMaxJob
const MaxResponse = htmllimits.VMMaxResponse
const Lifetime = 45

var ErrUnavailable = errors.New("microvm_unavailable")

// Failure exposes only a fixed operation and allowlisted service code. Never
// wrap SDK errors: they can contain URLs, request details or credentials.
type Failure struct{ Stage, Code string }

func (f *Failure) Error() string { return "microvm_unavailable:" + f.Stage + ":" + f.Code }
func (f *Failure) Unwrap() error { return ErrUnavailable }

func unavailable(stage string, cause error) error {
	code := "unavailable"
	var api smithy.APIError
	if errors.As(cause, &api) {
		switch api.ErrorCode() {
		case "AccessDeniedException", "ValidationException", "ResourceNotFoundException", "ConflictException", "TooManyRequestsException", "ServiceQuotaExceededException", "InternalServerException":
			code = api.ErrorCode()
		}
	}
	return &Failure{stage, code}
}

var imagePattern = regexp.MustCompile(`^arn:aws:lambda:us-east-2:[0-9]{12}:microvm-image:agent-pdf-html[-a-z0-9]*$`)
var endpointPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}\.lambda-microvm\.us-east-2\.on\.aws$`)
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,100}$`)

type API interface {
	RunMicrovm(context.Context, *vm.RunMicrovmInput, ...func(*vm.Options)) (*vm.RunMicrovmOutput, error)
	GetMicrovm(context.Context, *vm.GetMicrovmInput, ...func(*vm.Options)) (*vm.GetMicrovmOutput, error)
	CreateMicrovmAuthToken(context.Context, *vm.CreateMicrovmAuthTokenInput, ...func(*vm.Options)) (*vm.CreateMicrovmAuthTokenOutput, error)
	TerminateMicrovm(context.Context, *vm.TerminateMicrovmInput, ...func(*vm.Options)) (*vm.TerminateMicrovmOutput, error)
}

type Runner struct {
	API            API
	Image, Version string
	// Test-only injection; production builds use the fixed TLS client below.
	transport http.RoundTripper
}

func endpoint(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || !endpointPattern.MatchString(u.Host) || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return nil, ErrUnavailable
	}
	u.Path = "/convert"
	return u, nil
}

// Run keeps all customer content out of AWS lifecycle API parameters. The
// random idempotency token belongs to this attempt only. No execution role,
// shell ingress, pause/resume, or customer-specific snapshots are permitted.
func (r Runner) Run(ctx context.Context, payload []byte) ([]byte, error) {
	// Only a service-declared terminal startup failure can be retried. No job
	// payload/authentication has been sent, and cleanup must be confirmed first.
	// Both launches share the original work deadline; conversion is never replayed.
	work, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	var data []byte
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		retry := false
		data, err = r.runOnce(work, payload, &retry)
		if err == nil || !retry || work.Err() != nil {
			break
		}
	}
	return data, err
}

func (r Runner) runOnce(ctx context.Context, payload []byte, retry *bool) (data []byte, err error) {
	if r.API == nil || !imagePattern.MatchString(r.Image) || r.Version == "" || len(payload) == 0 || len(payload) > MaxJob {
		return nil, ErrUnavailable
	}
	started := time.Now()
	terminated := false
	// Durations only: extend the existing summary, without another log event,
	// customer URL/content, VM authentication token or per-customer metric series.
	var launchMS, readyMS, authMS, workerMS, cleanupMS int64
	defer func() {
		stage, code := "complete", ""
		var failure *Failure
		if errors.As(err, &failure) {
			stage, code = failure.Stage, failure.Code
		} else if err != nil {
			stage, code = "worker", "unavailable"
		}
		slog.InfoContext(ctx, "microvm_job", "request_id", telemetry.Trace(ctx), "stage", stage, "code", code, "termination_confirmed", terminated, "elapsed_ms", time.Since(started).Milliseconds(), "launch_ms", launchMS, "ready_wait_ms", readyMS, "auth_ms", authMS, "worker_ms", workerMS, "cleanup_ms", cleanupMS)
	}()
	var token [32]byte
	if _, err = rand.Read(token[:]); err != nil {
		return nil, ErrUnavailable
	}
	work, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	phaseStarted := time.Now()
	created, e := r.API.RunMicrovm(work, &vm.RunMicrovmInput{
		ImageIdentifier: aws.String(r.Image), ImageVersion: aws.String(r.Version), ClientToken: aws.String(hex.EncodeToString(token[:])),
		MaximumDurationInSeconds: aws.Int32(Lifetime),
		IdlePolicy:               &types.IdlePolicy{AutoResumeEnabled: aws.Bool(false), MaxIdleDurationSeconds: aws.Int32(60), SuspendedDurationSeconds: aws.Int32(0)},
		IngressNetworkConnectors: []string{"arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:ALL_INGRESS"},
		EgressNetworkConnectors:  []string{"arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:INTERNET_EGRESS"},
		Logging:                  &types.LoggingMemberDisabled{},
	})
	launchMS = time.Since(phaseStarted).Milliseconds()
	// A lost create response is bounded by the service-enforced lifetime. The
	// SDK retries with the SAME client token, preventing duplicate environments.
	if e != nil || created == nil || !idPattern.MatchString(aws.ToString(created.MicrovmId)) {
		return nil, unavailable("launch", e)
	}
	id := aws.ToString(created.MicrovmId)
	defer func() {
		cleanupStarted := time.Now()
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer done()
		if failure := r.terminate(cleanup, id); failure != nil {
			*retry = false
			data = nil
			err = errors.Join(err, failure)
		} else {
			terminated = true
		}
		cleanupMS = time.Since(cleanupStarted).Milliseconds()
	}()
	u, e := endpoint(aws.ToString(created.Endpoint))
	if e != nil || aws.ToString(created.ImageArn) != r.Image || aws.ToString(created.ImageVersion) != r.Version {
		return nil, unavailable("launch_response", nil)
	}
	phaseStarted = time.Now()
	readyReason := aws.ToString(created.StateReason)
	for created.State != types.MicrovmStateRunning {
		readyMS = time.Since(phaseStarted).Milliseconds()
		if created.State != types.MicrovmStatePending || pause(work) != nil {
			if created.State == types.MicrovmStateTerminated && readyReason == "Internal service error." && work.Err() == nil {
				*retry = true
				return nil, &Failure{Stage: "ready_state", Code: "InternalServerException"}
			}
			return nil, unavailable("ready_state", nil)
		}
		out, e := r.API.GetMicrovm(work, &vm.GetMicrovmInput{MicrovmIdentifier: aws.String(id)})
		if e != nil || out == nil {
			return nil, unavailable("ready_poll", e)
		}
		created.State = out.State
		readyReason = aws.ToString(out.StateReason)
	}
	readyMS = time.Since(phaseStarted).Milliseconds()
	phaseStarted = time.Now()
	auth, e := r.API.CreateMicrovmAuthToken(work, &vm.CreateMicrovmAuthTokenInput{MicrovmIdentifier: aws.String(id), ExpirationInMinutes: aws.Int32(1), AllowedPorts: []types.PortSpecification{&types.PortSpecificationMemberPort{Value: 8080}}})
	authMS = time.Since(phaseStarted).Milliseconds()
	if e != nil || auth == nil {
		return nil, unavailable("authenticate", e)
	}
	secret := auth.AuthToken["X-aws-proxy-auth"]
	if secret == "" || len(secret) > 16<<10 || strings.ContainsAny(secret, "\r\n\x00") {
		return nil, unavailable("auth_response", nil)
	}
	transport := r.transport
	if transport == nil {
		t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 25 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true, DisableKeepAlives: true}
		defer t.CloseIdleConnections()
		transport = t
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(work, http.MethodPost, u.String(), bytes.NewReader(payload))
	if e != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-aws-proxy-auth", secret)
	req.Header.Set("X-aws-proxy-port", "8080")
	phaseStarted = time.Now()
	response, e := client.Do(req)
	workerMS = time.Since(phaseStarted).Milliseconds()
	if e != nil {
		return nil, unavailable("request", nil)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" || response.ContentLength > MaxResponse {
		return nil, unavailable("response_headers", nil)
	}
	data, e = io.ReadAll(io.LimitReader(response.Body, MaxResponse+1))
	workerMS = time.Since(phaseStarted).Milliseconds()
	if e != nil || len(data) > MaxResponse || len(data) == 0 || jsonwire.Check(data, MaxResponse) != nil {
		return nil, unavailable("response_body", nil)
	}
	return data, nil
}

func pause(ctx context.Context) error {
	t := time.NewTimer(150 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r Runner) terminate(ctx context.Context, id string) error {
	if _, e := r.API.TerminateMicrovm(ctx, &vm.TerminateMicrovmInput{MicrovmIdentifier: aws.String(id)}); e != nil {
		return unavailable("terminate", e)
	}
	for {
		out, e := r.API.GetMicrovm(ctx, &vm.GetMicrovmInput{MicrovmIdentifier: aws.String(id)})
		if e != nil || out == nil {
			return unavailable("terminate_poll", e)
		}
		if out.State == types.MicrovmStateTerminated {
			return nil
		}
		if pause(ctx) != nil {
			return unavailable("terminate_wait", nil)
		}
	}
}
