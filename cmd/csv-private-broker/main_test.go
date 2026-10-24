package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"pdfservice/internal/csvcloud"
	"pdfservice/internal/csvwire"
	"strings"
	"testing"
	"time"
)

func testBootstrap(t *testing.T) []byte {
	t.Helper()
	run := strings.Repeat("a", 64)
	account := "999999999999"
	b := csvcloud.BrokerBootstrap{RunID: run, JobID: run, Account: account, Table: "utils-bot-csv-private-" + run[:16], Bucket: "utils-csv-" + account + "-" + run[:24], Cluster: "arn:aws:ecs:us-east-2:" + account + ":cluster/utils-bot-csv-trial", Definition: "arn:aws:ecs:us-east-2:" + account + ":task-definition/utils-bot-csv-private-" + run[:16] + "-worker:1", Subnet: "subnet-00000000000000001", Prefix: "10.88.0.0/24", Until: time.Now().Add(10 * time.Minute).Unix(), Review: csvcloud.WireReview{Account: account, RunID: run, Image: account + ".dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-private@sha256:" + strings.Repeat("c", 64), ExecutionRole: "arn:aws:iam::" + account + ":role/utils-bot-csv-private-" + run[:16] + "-worker-execution", SecretARN: "arn:aws:ssm:us-east-2:" + account + ":parameter/utils-bot/csv-private/" + run + "/tls", SyntheticOnly: true}, Request: csvwire.Request{Version: 1, Operation: "transform", Options: json.RawMessage(`{"column":"id","op":"upper"}`), Files: []csvwire.File{{Slot: "file", Bytes: 8, SHA256: strings.Repeat("b", 64)}}}, NetworkPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestStartupFailuresBlockLaterEffectsAndClearBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		code, harden, load, process, cleared int
	}{
		{"gate", 78, 0, 0, 0, 0}, {"uid", 78, 0, 0, 0, 0}, {"hardening", 79, 1, 0, 0, 0}, {"bootstrap", 80, 1, 0, 0, 0}, {"config", 81, 1, 1, 0, 1}, {"processing", 82, 1, 1, 1, 1}, {"spool", 83, 0, 0, 0, 1}, {"success", 0, 1, 1, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := testBootstrap(t)
			if tc.name == "bootstrap" {
				raw = []byte("private-secret-canary")
			}
			h, l, p, c := 0, 0, 0, 0
			secret := errors.New("private-secret-canary")
			runtime := brokerRuntime{now: time.Now, harden: func() error {
				h++
				if tc.name == "hardening" {
					return secret
				}
				return nil
			}, initSpool: func() error { return secret }, clearEnvironment: func() { c++ }, load: func() (aws.Config, error) {
				l++
				for _, b := range raw {
					if b != 0 {
						t.Fatal("bootstrap remained before credential load")
					}
				}
				if tc.name == "config" {
					return aws.Config{}, secret
				}
				return aws.Config{}, nil
			}, process: func(context.Context, csvcloud.BrokerBootstrap, aws.Config) error {
				p++
				if c != 1 {
					t.Fatal("environment not cleared before process")
				}
				if tc.name == "processing" {
					return secret
				}
				return nil
			}}
			uid := 65532
			if tc.name == "uid" {
				uid = 1
			}
			code := runBroker(tc.name == "spool", tc.name != "gate", uid, raw, runtime)
			if code != tc.code || h != tc.harden || l != tc.load || p != tc.process || c != tc.cleared {
				t.Fatal("startup effect boundary violated", code, h, l, p, c)
			}
			for _, b := range raw {
				if b != 0 {
					t.Fatal("bootstrap remained after failure")
				}
			}
		})
	}
}
