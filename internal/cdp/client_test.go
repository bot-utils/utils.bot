package cdp

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

const testPayTo = "0x2222222222222222222222222222222222222222"

func testRequirements(t *testing.T) types.PaymentRequirements {
	t.Helper()
	cfg, err := protocol.NewConfig(protocol.ModeSepolia, testPayTo)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Requirements()
}

func testClient(t *testing.T) (*Client, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newClient("test-key-id", base64.StdEncoding.EncodeToString(key), testPayTo)
	if err != nil {
		t.Fatal(err)
	}
	c.config, _ = protocol.NewConfig(protocol.ModeSepolia, testPayTo)
	c.now = func() time.Time { return time.Unix(1800000000, 0) }
	return c, key
}

func TestJWTBindingsAndNativeSignatures(t *testing.T) {
	c, ed := testClient(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(ec)
	p := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	ecClient, err := newClient("ec-key", string(p), testPayTo)
	if err != nil {
		t.Fatal(err)
	}
	ecClient.now = c.now
	for _, tc := range []*Client{c, ecClient} {
		jwt, err := tc.token("GET", basePath+"supported")
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Fatal("invalid JWT")
		}
		head, _ := base64.RawURLEncoding.DecodeString(parts[0])
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		var h map[string]any
		var v map[string]any
		_ = json.Unmarshal(head, &h)
		_ = json.Unmarshal(claims, &v)
		if h["kid"] != tc.keyID || len(h["nonce"].(string)) != 32 || v["iss"] != "cdp" || v["sub"] != tc.keyID || v["exp"].(float64)-v["nbf"].(float64) != 120 || v["uris"].([]any)[0] != "GET "+host+basePath+"supported" {
			t.Fatal("unbound JWT claims")
		}
		message := []byte(parts[0] + "." + parts[1])
		if tc == c {
			if !ed25519.Verify(ed.Public().(ed25519.PublicKey), message, sig) {
				t.Fatal("bad Ed25519 signature")
			}
		} else {
			hash := sha256.Sum256(message)
			if len(sig) != 64 || !ecdsa.Verify(&ec.PublicKey, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Fatal("bad ES256 signature")
			}
		}
		second, _ := tc.token("GET", basePath+"supported")
		if second == jwt {
			t.Fatal("nonce reused")
		}
	}
	if _, err := c.token("GET", "/other"); err == nil {
		t.Fatal("arbitrary signing path accepted")
	}
	if fmt.Sprintf("%#v", c) != "Coinbase client [redacted]" {
		t.Fatal("client formatting leaks credentials")
	}
	bad := append(ed25519.PrivateKey(nil), ed...)
	bad[len(bad)-1] ^= 1
	if _, err := newClient("test", base64.StdEncoding.EncodeToString(bad), testPayTo); err == nil {
		t.Fatal("corrupt key public half accepted")
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestBoundedResponsesAndNoCredentialRedirect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"unauthorized", 403, "secret echoed by provider", ErrUnauthorized},
		{"limited", 429, "provider diagnostic", ErrUnavailable},
		{"supported bad request", 400, `{"kinds":[{"x402Version":2,"scheme":"exact","network":"eip155:84532"}]}`, ErrUnavailable},
		{"oversize", 200, strings.Repeat(" ", maxResponse+1), ErrResponse},
		{"ambiguous", 200, `{"kinds":[],"kinds":[]}`, ErrResponse},
		{"missing kinds", 200, `{}`, ErrResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testClient(t)
			c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != host || r.URL.Scheme != "https" || r.Header.Get("Authorization") == "" {
					t.Fatal("unsafe request")
				}
				return response(r, tc.status, tc.body), nil
			})
			_, err := c.Check(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("wrong sanitized error: %v", err)
			}
		})
	}
	c, _ := testClient(t)
	calls := 0
	c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		res := response(r, 302, "")
		res.Header.Set("Location", "https://untrusted.example/")
		return res, nil
	})
	_, err := c.Check(context.Background())
	if !errors.Is(err, ErrUnavailable) || calls != 1 {
		t.Fatal("redirect leaked bearer credentials")
	}
}

func TestHTTP400CanOnlyRejectPayments(t *testing.T) {
	p := types.PaymentPayload{X402Version: 2, Accepted: testRequirements(t)}
	a := evm.ExactEIP3009Payload{}
	a.Authorization.From = testPayTo
	for _, tc := range []struct {
		name, endpoint, body string
		wantError            bool
	}{
		{"verify rejection", "verify", `{"isValid":false,"invalidReason":"insufficient_funds","invalidMessage":"private diagnostic"}`, false},
		{"verify approval", "verify", `{"isValid":true}`, true},
		{"verify missing result", "verify", `{}`, true},
		{"verify conflicting result", "verify", `{"isValid":false,"isValid":true}`, true},
		{"settle rejection", "settle", `{"success":false,"errorReason":"insufficient_funds","errorMessage":"private diagnostic"}`, false},
		{"settle pending evidence", "settle", `{"success":false,"errorReason":"settlement_pending","transaction":"0x` + strings.Repeat("a", 64) + `","network":"` + protocol.Network + `","payer":"` + testPayTo + `"}`, false},
		{"settle pending missing identity", "settle", `{"success":false,"errorReason":"settlement_pending","transaction":"0x` + strings.Repeat("a", 64) + `"}`, true},
		{"settle pending wrong payer", "settle", `{"success":false,"errorReason":"settlement_pending","transaction":"0x` + strings.Repeat("a", 64) + `","network":"` + protocol.Network + `","payer":"0x` + strings.Repeat("3", 40) + `"}`, true},
		{"settle approval", "settle", `{"success":true}`, true},
		{"settle missing result", "settle", `{}`, true},
		{"settle conflicting result", "settle", `{"success":false,"success":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testClient(t)
			c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				return response(r, 400, tc.body), nil
			})
			var err error
			if tc.endpoint == "verify" {
				var valid bool
				valid, err = c.Verify(context.Background(), p, a)
				if valid {
					t.Fatal("HTTP 400 approved payment")
				}
			} else {
				out, e := c.Settle(context.Background(), p, a)
				err = e
				if out != nil && (out.Success || out.ErrorMessage != "") {
					t.Fatal("HTTP 400 approved payment or exposed diagnostics")
				}
				if tc.name == "settle pending evidence" && (out == nil || out.Transaction == "" || out.ErrorReason != "settlement_pending") {
					t.Fatal("pending evidence lost")
				}
			}
			if (err != nil) != tc.wantError || err != nil && !errors.Is(err, ErrResponse) {
				t.Fatalf("wrong rejection handling: %v", err)
			}
		})
	}
}

func TestHTTP200PaymentApprovalRequiresMatchingSettlement(t *testing.T) {
	c, _ := testClient(t)
	p := types.PaymentPayload{X402Version: 2, Accepted: testRequirements(t)}
	a := evm.ExactEIP3009Payload{}
	a.Authorization.From = testPayTo
	tx := "0x" + strings.Repeat("a", 64)
	c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == basePath+"verify" {
			return response(r, 200, `{"isValid":true,"payer":"`+a.Authorization.From+`"}`), nil
		}
		return response(r, 200, `{"success":true,"transaction":"`+tx+`","network":"`+protocol.Network+`","payer":"`+a.Authorization.From+`","extra":{"private":"provider detail"},"extensions":{"private":"provider extension"}}`), nil
	})
	valid, err := c.Verify(context.Background(), p, a)
	if err != nil || !valid {
		t.Fatalf("valid verification rejected: %v", err)
	}
	c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		return response(r, 200, `{"isValid":true}`), nil
	})
	if valid, err := c.Verify(context.Background(), p, a); valid || !errors.Is(err, ErrResponse) {
		t.Fatalf("payerless verification approved: valid=%v err=%v", valid, err)
	}
	c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		return response(r, 200, `{"success":true,"transaction":"`+tx+`","network":"`+protocol.Network+`","payer":"`+a.Authorization.From+`"}`), nil
	})
	out, err := c.Settle(context.Background(), p, a)
	if err != nil || out == nil || !out.Success || out.Transaction != tx || out.ErrorMessage != "" || out.Extra != nil || out.Extensions != nil {
		t.Fatalf("valid settlement rejected: %v", err)
	}
	a.Authorization.From = "0x" + strings.Repeat("3", 40)
	// The response still names the original payer: a valid transaction for a
	// different payer must never authorize this request.
	c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		return response(r, 200, `{"success":true,"transaction":"`+tx+`","network":"`+protocol.Network+`","payer":"`+testPayTo+`"}`), nil
	})
	if _, err := c.Settle(context.Background(), p, a); !errors.Is(err, ErrResponse) {
		t.Fatal("other payer's settlement approved")
	}
}

func TestProviderContractAndMainnetGuard(t *testing.T) {
	c, _ := testClient(t)
	calls := 0
	p := types.PaymentPayload{X402Version: 2, Accepted: testRequirements(t)}
	a := evm.ExactEIP3009Payload{}
	a.Authorization.From = testPayTo
	c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case basePath + "supported":
			return response(r, 200, `{"kinds":[{"x402Version":2,"scheme":"exact","network":"eip155:84532"},{"x402Version":2,"scheme":"exact","network":"eip155:8453"}]}`), nil
		case basePath + "verify":
			var b map[string]json.RawMessage
			if json.NewDecoder(r.Body).Decode(&b) != nil || b["paymentPayload"] == nil || b["paymentRequirements"] == nil {
				t.Fatal("incorrect x402 request envelope")
			}
			return response(r, 200, `{"isValid":false,"invalidReason":"insufficient_funds"}`), nil
		case basePath + "settle":
			return response(r, 200, `{"success":false,"errorReason":"settlement_pending","errorMessage":"must not leak","transaction":"0x`+strings.Repeat("a", 64)+`","network":"eip155:84532","payer":"`+testPayTo+`"}`), nil
		}
		t.Fatal("unexpected endpoint")
		return nil, nil
	})
	support, err := c.Check(context.Background())
	if err != nil || !support.Base || !support.BaseSepolia {
		t.Fatal("supported schema mismatch")
	}
	valid, err := c.Verify(context.Background(), p, a)
	if err != nil || valid {
		t.Fatal("invalid payment approved")
	}
	settled, err := c.Settle(context.Background(), p, a)
	if err != nil || settled.Success || settled.ErrorReason != "settlement_pending" || settled.ErrorMessage != "" {
		t.Fatal("pending settlement converted to approval/lost evidence")
	}
	p.Accepted.Network = "eip155:8453"
	before := calls
	if _, err = c.Settle(context.Background(), p, a); err == nil || calls != before {
		t.Fatal("mainnet sent without explicit configuration")
	}
	for _, body := range []string{`{}`, `{"isValid":true,"payer":"wrong"}`} {
		c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) { return response(r, 200, body), nil })
		p.Accepted = testRequirements(t)
		if _, err = c.Verify(context.Background(), p, a); err != ErrResponse {
			t.Fatal("incomplete verification accepted")
		}
	}
	for _, body := range []string{`{}`, `{"success":true}`, `{"success":false,"success":true}`} {
		c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) { return response(r, 200, body), nil })
		if _, err = c.Settle(context.Background(), p, a); err != ErrResponse {
			t.Fatal("malformed settlement accepted")
		}
	}
}

type parametersFunc func(context.Context, *ssm.GetParametersInput) (*ssm.GetParametersOutput, error)

func (f parametersFunc) GetParameters(ctx context.Context, in *ssm.GetParametersInput, _ ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	return f(ctx, in)
}
func TestExactEncryptedParameterReads(t *testing.T) {
	_, key := testClient(t)
	values := []string{"test-key", base64.StdEncoding.EncodeToString(key), testPayTo}
	makeOutput := func() *ssm.GetParametersOutput {
		out := &ssm.GetParametersOutput{}
		for i, n := range parameterNames {
			out.Parameters = append(out.Parameters, ssmtypes.Parameter{Name: aws.String(n), Value: aws.String(values[i]), Type: ssmtypes.ParameterTypeSecureString})
		}
		return out
	}
	api := parametersFunc(func(_ context.Context, in *ssm.GetParametersInput) (*ssm.GetParametersOutput, error) {
		if !aws.ToBool(in.WithDecryption) || len(in.Names) != 3 || strings.Join(in.Names, ",") != strings.Join(parameterNames, ",") {
			t.Fatal("broader or plaintext parameter reads")
		}
		return makeOutput(), nil
	})
	if _, err := FromParameters(context.Background(), api); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*ssm.GetParametersOutput){func(o *ssm.GetParametersOutput) { o.Parameters = o.Parameters[:2] }, func(o *ssm.GetParametersOutput) { o.Parameters[0].Type = ssmtypes.ParameterTypeString }, func(o *ssm.GetParametersOutput) { o.Parameters[0].Name = aws.String("/pdf/coinbaseProjectId") }, func(o *ssm.GetParametersOutput) { o.Parameters[1] = o.Parameters[0] }} {
		out := makeOutput()
		alter(out)
		if _, err := FromParameters(context.Background(), parametersFunc(func(context.Context, *ssm.GetParametersInput) (*ssm.GetParametersOutput, error) { return out, nil })); err != ErrParameters {
			t.Fatal("incomplete/unexpected parameter configuration accepted")
		}
	}
	if _, err := FromParameters(context.Background(), parametersFunc(func(context.Context, *ssm.GetParametersInput) (*ssm.GetParametersOutput, error) {
		return nil, errors.New("secret must not appear")
	})); err != ErrParameters {
		t.Fatal("upstream error leaked")
	}
}

func TestCDPSettlementRequiresExplicitMatchingConfiguration(t *testing.T) {
	c, _ := testClient(t)
	calls := 0
	c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return response(r, 200, `{"success":false}`), nil
	})
	c.config = protocol.Config{}
	p := types.PaymentPayload{X402Version: 2, Accepted: protocol.Requirements()}
	if _, err := c.Settle(context.Background(), p, evm.ExactEIP3009Payload{}); !errors.Is(err, ErrCredentials) || calls != 0 {
		t.Fatal("mock submitted settlement")
	}
	if _, err := c.ForPayments(protocol.Config{}); !errors.Is(err, ErrCredentials) {
		t.Fatal("mock enabled CDP")
	}
	base, _ := protocol.NewConfig(protocol.ModeBase, testPayTo)
	bound, err := c.ForPayments(base)
	if err != nil {
		t.Fatal(err)
	}
	if c.config.Mode() != protocol.ModeMock || bound.config.Mode() != protocol.ModeBase {
		t.Fatal("shared client mutated")
	}
	wrong, _ := protocol.NewConfig(protocol.ModeBase, "0x3333333333333333333333333333333333333333")
	if _, err := c.ForPayments(wrong); !errors.Is(err, ErrCredentials) {
		t.Fatal("wrong SSM payee accepted")
	}
	p.Accepted = base.Requirements()
	if _, err := bound.Settle(context.Background(), p, evm.ExactEIP3009Payload{}); err != nil || calls != 1 {
		t.Fatal("explicit Base settlement unavailable")
	}
	p.Accepted = protocol.Requirements()
	before := calls
	if _, err := bound.Settle(context.Background(), p, evm.ExactEIP3009Payload{}); err == nil || calls != before {
		t.Fatal("testnet payload reached mainnet provider")
	}
}
