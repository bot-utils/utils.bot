// A bounded operator process, never the shared API or a container sidecar.
package main

import (
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/csvcloud"
	"pdfservice/internal/jsonwire"
)

func main() {
	var in struct {
		Run                       csvcloud.PrivateAPIRun
		VerifierPath, VerifierSHA string
		ProofKey                  []byte
		VerifierCredentials       struct {
			AccessKeyID, SecretAccessKey, SessionToken string
			Expires                                    time.Time
		}
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 16<<10+1))
	if e != nil || len(raw) > 16<<10 || jsonwire.Decode(raw, &in, 16<<10) != nil || len(in.ProofKey) != ed25519.PrivateKeySize || in.VerifierCredentials.SessionToken == "" || in.VerifierCredentials.Expires.Before(time.Now().Add(12*time.Minute)) {
		os.Exit(78)
	}
	clear(raw)
	cfg, e := awsenv.Load()
	os.Clearenv()
	if e != nil {
		os.Exit(78)
	}
	verifier := csvcloud.VerifierProcess{Executable: in.VerifierPath, BinarySHA: in.VerifierSHA, RunID: in.Run.ID, JobID: in.Run.ID, Key: ed25519.PrivateKey(in.ProofKey), Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		v := in.VerifierCredentials
		return aws.Credentials{AccessKeyID: v.AccessKeyID, SecretAccessKey: v.SecretAccessKey, SessionToken: v.SessionToken, CanExpire: true, Expires: v.Expires}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	coordinator, e := csvcloud.NewPrivateUploadCoordinator(ctx, in.Run, cfg, verifier)
	if e != nil {
		os.Exit(78)
	}
	if _, e = io.WriteString(os.Stdout, "CSV_UPLOAD_READY "+in.Run.ID+"\n"); e != nil {
		os.Exit(78)
	}
	if coordinator.Run(ctx) != nil {
		os.Exit(78)
	}
	clear(in.ProofKey)
}
