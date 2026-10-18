package awsenv

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestECSCredentialRefreshAndRedirectRefusal(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		calls := 0
		client := credentialClient()
		client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Host != "169.254.170.2" || r.URL.Path != "/v2/credentials/fixture" {
				t.Fatal("unexpected credential destination")
			}
			if redirect {
				return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{"http://untrusted.invalid/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}
			expiry := time.Now().Add(time.Hour)
			if calls == 1 {
				expiry = time.Now().Add(-time.Minute)
			}
			body := `{"AccessKeyId":"synthetic","SecretAccessKey":"test-only","Token":"token","Expiration":"` + expiry.UTC().Format(time.RFC3339) + `"}`
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})
		cfg, err := loadWithClient(environment(map[string]string{"AWS_REGION": "us-east-2", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/fixture"}), client)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		first, err := cfg.Credentials.Retrieve(ctx)
		if redirect {
			if err == nil || calls != 1 {
				t.Fatal("credential redirect accepted")
			}
		} else {
			if err != nil || first.AccessKeyID != "synthetic" {
				t.Fatal("initial credential read failed", err)
			}
			second, err := cfg.Credentials.Retrieve(ctx)
			if err != nil || second.Expired() || calls != 2 {
				t.Fatal("expired credentials not refreshed", err)
			}
		}
		cancel()
	}
}

func environment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}
func TestEnvironmentCredentials(t *testing.T) {
	cfg, err := load(environment(map[string]string{"AWS_REGION": "us-east-2", "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "synthetic", "AWS_SESSION_TOKEN": "token"}))
	if err != nil {
		t.Fatal(err)
	}
	c, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "test" || c.SessionToken != "token" || cfg.Region != "us-east-2" {
		t.Fatalf("credential selection failed: %v", err)
	}
}
func TestRejectUnexpectedCredentialSources(t *testing.T) {
	for _, values := range []map[string]string{
		{"AWS_REGION": "us-east-2"},
		{"AWS_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "synthetic"},
		{"AWS_REGION": "us-east-2", "AWS_ACCESS_KEY_ID": "test"},
		{"AWS_REGION": "us-east-2", "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://untrusted.invalid/"},
		{"AWS_REGION": "us-east-2", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "https://untrusted.invalid/v2/credentials/test"},
		{"AWS_REGION": "us-east-2", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/../other"},
		{"AWS_REGION": "us-east-2", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/test?redirect=1"},
	} {
		if _, err := load(environment(values)); err == nil {
			t.Fatal("unexpected credential source accepted")
		}
	}
	if _, err := load(environment(map[string]string{"AWS_REGION": "us-east-2", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/fixture"})); err != nil {
		t.Fatal("normal ECS credentials rejected", err)
	}
}

func TestLocalStackOverrideRequiresDummyCredentials(t *testing.T) {
	env := map[string]string{"AWS_REGION": "us-east-2", "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_ENDPOINT_URL": "http://localhost:4566"}
	cfg, err := load(environment(env))
	if err != nil || cfg.BaseEndpoint == nil || *cfg.BaseEndpoint != env["AWS_ENDPOINT_URL"] {
		t.Fatal("local override rejected", err)
	}
	env["AWS_ENDPOINT_URL"] = "https://untrusted.invalid"
	if _, err := load(environment(env)); err == nil {
		t.Fatal("remote credential redirect accepted")
	}
	env["AWS_ENDPOINT_URL"] = "http://localhost:4566"
	env["AWS_SECRET_ACCESS_KEY"] = "real-looking"
	if _, err := load(environment(env)); err == nil {
		t.Fatal("real credentials sent to local override")
	}
}

func TestCredentialsBypassEnvironmentProxies(t *testing.T) {
	client := credentialClient()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("credential fetch can use an environment proxy")
	}
	if client.CheckRedirect == nil || client.Timeout == 0 {
		t.Fatal("unbounded credential fetch")
	}
}

func TestServiceRequestsDoNotFollowRedirectsOrUseProxies(t *testing.T) {
	client := serviceClient()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || client.Timeout == 0 || transport.MaxConnsPerHost == 0 {
		t.Fatal("service transport is not bounded and TLS-only by default")
	}
	calls := 0
	client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{"https://example.invalid/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	r, _ := http.NewRequest("POST", "https://lambda.us-east-2.amazonaws.com/", nil)
	r.Header.Set("Authorization", "synthetic-test-value")
	response, err := client.Do(r)
	if err != nil || response.StatusCode != 307 || calls != 1 {
		t.Fatal("signed service request followed a redirect", err)
	}
	_ = response.Body.Close()
	cfg, err := load(environment(map[string]string{"AWS_REGION": "us-east-2", "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}))
	if err != nil || cfg.HTTPClient == nil {
		t.Fatal("SDK configuration omitted hardened transport", err)
	}
}
