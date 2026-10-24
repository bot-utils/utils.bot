package csvcloud

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func brokerStageFixture(t *testing.T) BrokerBootstrap {
	t.Helper()
	now := time.Now()
	_, identity, e := privateIdentities(now)
	if e != nil {
		t.Fatal(e)
	}
	run := ID()
	account := "999999999999"
	w := WireReview{Account: account, RunID: run, Image: account + ".dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-private@sha256:" + ID(), ExecutionRole: "arn:aws:iam::" + account + ":role/utils-bot-csv-private-" + run[:16] + "-worker-execution", SecretARN: "arn:aws:ssm:us-east-2:" + account + ":parameter/utils-bot/csv-private/" + run + "/tls", SyntheticOnly: true}
	fixture, e := privateSmallFixture("transform")
	if e != nil {
		t.Fatal(e)
	}
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return BrokerBootstrap{RunID: run, JobID: run, Account: account, Table: "utils-bot-csv-private-" + run[:16], Bucket: "utils-csv-" + account + "-" + run[:24], Cluster: "arn:aws:ecs:us-east-2:" + account + ":cluster/utils-bot-csv-trial", Definition: "arn:aws:ecs:us-east-2:" + account + ":task-definition/utils-bot-csv-private-" + run[:16] + "-worker:1", Subnet: privateTrialSubnet, Prefix: "10.88.0.0/24", Until: now.Add(10 * time.Minute).Unix(), Review: w, Request: fixture.Request, Identity: identity, NetworkPublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func TestBrokerFailureStagesStopBeforeFurtherEffectsAndHideProviderText(t *testing.T) {
	secret := "secret /csv/jobs/private X-CSV-Test-Key https://private.invalid/signed?token=secret"
	for _, tc := range []struct {
		name                string
		status, code, calls int
		body                string
	}{
		{"invalid bootstrap", 200, 80, 0, `{}`},
		{"invalid client config", 200, 81, 0, `{}`},
		{"metadata access denied", 400, 88, 1, `{"__type":"AccessDeniedException","message":"` + secret + `"}`},
		{"missing job", 200, 85, 1, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := brokerStageFixture(t)
			calls := 0
			cfg := sdkConfig(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "dynamodb.us-east-2.amazonaws.com" || r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.GetItem" {
					t.Fatal("unexpected service effect")
				}
				return response(tc.status, tc.body, nil), nil
			})
			if tc.name == "invalid bootstrap" {
				b.RunID = "invalid"
			}
			if tc.name == "invalid client config" {
				cfg.Region = "us-east-1"
			}
			err := ProcessSyntheticBroker(context.Background(), b, cfg)
			if err == nil || BrokerFailureExitCode(err) != tc.code || calls != tc.calls {
				t.Fatal("incorrect bounded failure stage", calls, BrokerFailureExitCode(err))
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "/csv/") {
				t.Fatal("provider text exposed")
			}
		})
	}
	if BrokerFailureExitCode(errors.New(secret)) != 82 || BrokerFailureExitCode(brokerFailure(255, errors.New(secret))) != 82 || BrokerFailureExitCode(nil) != 0 {
		t.Fatal("nonallowlisted stage code exposed")
	}
}

func TestBrokerTLSAndRetiredProcessingStagesDoNotWrite(t *testing.T) {
	for _, brokenTLS := range []bool{true, false} {
		t.Run(map[bool]string{true: "TLS", false: "retired_job"}[brokenTLS], func(t *testing.T) {
			b := brokerStageFixture(t)
			_, j, q, _, _ := processorFixture(t)
			b.JobID = j.ID
			b.RunID = j.ID
			b.Review.RunID = j.ID
			b.Request = q
			b.Table = "utils-bot-csv-private-" + j.ID[:16]
			b.Bucket = "utils-csv-" + b.Account + "-" + j.ID[:24]
			b.Review.ExecutionRole = "arn:aws:iam::" + b.Account + ":role/utils-bot-csv-private-" + j.ID[:16] + "-worker-execution"
			b.Review.SecretARN = "arn:aws:ssm:us-east-2:" + b.Account + ":parameter/utils-bot/csv-private/" + j.ID + "/tls"
			b.Definition = "arn:aws:ecs:us-east-2:" + b.Account + ":task-definition/utils-bot-csv-private-" + j.ID[:16] + "-worker:1"
			if brokenTLS {
				b.Identity.PrivateKey = "invalid-secret-canary"
			} else {
				j.Artifact = "DELETING"
			}
			attributes := map[string]any{}
			for key, value := range row(j) {
				switch v := value.(type) {
				case *d.AttributeValueMemberS:
					attributes[key] = map[string]string{"S": v.Value}
				case *d.AttributeValueMemberN:
					attributes[key] = map[string]string{"N": v.Value}
				case *d.AttributeValueMemberB:
					attributes[key] = map[string]string{"B": base64.StdEncoding.EncodeToString(v.Value)}
				}
			}
			body, _ := json.Marshal(map[string]any{"Item": attributes})
			calls := 0
			cfg := sdkConfig(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.GetItem" {
					t.Fatal("unexpected write or service effect")
				}
				return response(200, string(body), nil), nil
			})
			err := ProcessSyntheticBroker(context.Background(), b, cfg)
			want, count := 87, 2
			if brokenTLS {
				want, count = 86, 1
			}
			if err == nil || BrokerFailureExitCode(err) != want || calls != count || strings.Contains(err.Error(), "canary") {
				t.Fatal("unsafe stage or service effect", BrokerFailureExitCode(err), calls)
			}
		})
	}
}

func TestMetadataExitClassesNeverExposeProviderText(t *testing.T) {
	secret := "private-provider-secret /csv/jobs/private?token=secret"
	for _, tc := range []struct {
		err  error
		code int
	}{
		{&smithy.GenericAPIError{Code: "AccessDeniedException", Message: secret}, 88},
		{errors.New("credential " + secret), 89},
		{&net.DNSError{Err: secret, Name: "private.invalid"}, 90},
		{x509.UnknownAuthorityError{}, 91},
		{&smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: secret}, 92},
		{&smithy.GenericAPIError{Code: "ThrottlingException", Message: secret}, 93},
		{context.DeadlineExceeded, 94},
		{&smithy.GenericAPIError{Code: "InternalFailure", Message: secret}, 95},
		{errors.New(secret), 84},
	} {
		err := brokerFailure(84, tc.err)
		if BrokerFailureExitCode(err) != tc.code || err.Error() != "csv_private_broker_failed" || strings.Contains(err.Error(), secret) {
			t.Fatal("metadata failure privacy or classification changed")
		}
	}
}
