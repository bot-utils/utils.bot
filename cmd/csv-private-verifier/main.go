// A short-lived local verifier process, never a sidecar or customer-file worker.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"os"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/csvcloud"
	"pdfservice/internal/jsonwire"
	"time"
)

func main() {
	var expected csvcloud.VerifierScope
	encoded := os.Getenv("CSV_VERIFIER_SCOPE")
	keyFD := os.Getenv("CSV_VERIFIER_KEY_FD")
	_ = os.Unsetenv("CSV_VERIFIER_SCOPE")
	_ = os.Unsetenv("CSV_VERIFIER_KEY_FD")
	if keyFD != "4" {
		os.Exit(78)
	}
	keyFile := os.NewFile(4, "private-signing-key")
	key, e := io.ReadAll(io.LimitReader(keyFile, 65))
	keyFile.Close()
	if e != nil || len(key) != ed25519.PrivateKeySize || jsonwire.Decode([]byte(encoded), &expected, 4096) != nil {
		os.Exit(78)
	}

	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if e != nil || len(raw) > 4096 {
		os.Exit(78)
	}
	config, e := awsenv.Load()
	os.Clearenv()
	if e != nil {
		os.Exit(78)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if expected.Kind == "bucket" {
		var binding csvcloud.BucketBinding
		if jsonwire.Decode(raw, &binding, 4096) != nil || binding.RunID != expected.RunID || binding.JobID != expected.JobID || binding.Bucket != expected.Bucket || binding.Account != expected.Account {
			os.Exit(78)
		}
		proof, e := csvcloud.SignBucketProof(ctx, binding, ed25519.PrivateKey(key), csvcloud.BucketAbsence{Client: s3.NewFromConfig(config), Bucket: expected.Bucket, Account: expected.Account})
		clear(key)
		if e != nil || json.NewEncoder(os.Stdout).Encode(proof) != nil {
			os.Exit(78)
		}
		return
	}
	var binding csvcloud.NetworkBinding
	if expected.Kind != "network" || jsonwire.Decode(raw, &binding, 4096) != nil || binding.RunID != expected.RunID || binding.JobID != expected.JobID || binding.TaskARN != expected.TaskARN {
		os.Exit(78)
	}
	reader, e := csvcloud.NewEC2Reader(config)
	if e != nil {
		os.Exit(78)
	}
	observer := csvcloud.StoppedObserver{Client: ecs.NewFromConfig(config), Cluster: expected.Cluster, TaskARN: expected.TaskARN, Definition: expected.Definition, Group: expected.Group, StartedBy: expected.StartedBy}
	proof, e := csvcloud.SignNetworkProof(ctx, binding, ed25519.PrivateKey(key), observer.Observe, reader, time.Now())
	clear(key)
	if e != nil || json.NewEncoder(os.Stdout).Encode(proof) != nil {
		os.Exit(78)
	}
}
