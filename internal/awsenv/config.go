// Package awsenv selects only the credentials used by this Lambda/Fargate app.
package awsenv

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

func Load() (aws.Config, error) { return load(os.Getenv) }

func load(get func(string) string) (aws.Config, error) {
	return loadWithClient(get, credentialClient())
}

func credentialClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext:  (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Signed service requests use no environment proxy and never follow redirects.
// Official regional endpoints are selected by the SDK; a LocalStack override
// remains possible only with the existing dummy-credential checks below.
func serviceClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second, IdleConnTimeout: 60 * time.Second,
		MaxIdleConns: 16, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 16, ForceAttemptHTTP2: true,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func loadWithClient(get func(string) string, client *http.Client) (aws.Config, error) {
	region := get("AWS_REGION")
	if region == "" {
		region = get("AWS_DEFAULT_REGION")
	}
	if region != "us-east-2" {
		return aws.Config{}, errors.New("AWS_REGION must be us-east-2")
	}
	key, secret, token := get("AWS_ACCESS_KEY_ID"), get("AWS_SECRET_ACCESS_KEY"), get("AWS_SESSION_TOKEN")
	var provider aws.CredentialsProvider
	if key != "" || secret != "" || token != "" {
		if key == "" || secret == "" {
			return aws.Config{}, errors.New("incomplete environment credentials")
		}
		provider = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: key, SecretAccessKey: secret, SessionToken: token, Source: "Environment"}, nil
		})
	} else {
		path := get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
		u, err := url.Parse(path)
		if err != nil || !strings.HasPrefix(path, "/v2/credentials/") || u.Host != "" || u.Scheme != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != path || strings.Contains(path, "..") {
			return aws.Config{}, errors.New("missing or invalid ECS credential path")
		}
		provider = endpointcreds.New("http://169.254.170.2"+path, func(o *endpointcreds.Options) {
			o.HTTPClient = client
		})
	}
	cfg := aws.Config{Region: region, Credentials: aws.NewCredentialsCache(provider), HTTPClient: serviceClient()}
	if endpoint := get("AWS_ENDPOINT_URL"); endpoint != "" {
		u, err := url.Parse(endpoint)
		local := err == nil && (u.Hostname() == "localhost" || u.Hostname() == "localstack" || net.ParseIP(u.Hostname()).IsLoopback())
		if !local || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || key != "test" || secret != "test" || token != "" {
			return aws.Config{}, errors.New("LocalStack endpoint requires a local host and test-only credentials")
		}
		cfg.BaseEndpoint = aws.String(endpoint)
	}
	return cfg, nil
}
