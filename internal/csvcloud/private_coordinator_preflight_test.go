package csvcloud

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/jsonwire"
)

// Explicit read-only startup check: no admission, upload, queue or RunTask call.
func TestPrivateAWSCoordinatorReadinessOnly(t *testing.T) {
	id := os.Getenv("CSV_PRIVATE_COORDINATOR_READONLY_PREFLIGHT")
	if id == "" {
		t.Skip("explicit private read-only coordinator preflight required")
	}
	until, err := strconv.ParseInt(os.Getenv("CSV_PRIVATE_RESOURCES_UNTIL"), 10, 64)
	if !opaque(id) || err != nil || until <= time.Now().Unix() || until > time.Now().Add(2*time.Hour).Unix() {
		t.Fatal("invalid private preflight scope")
	}
	var credentials struct {
		AccessKeyID, SecretAccessKey, SessionToken string
		Expires                                    time.Time
	}
	if jsonwire.Decode([]byte(os.Getenv("CSV_PRIVATE_VERIFIER_CREDENTIALS")), &credentials, 8192) != nil || credentials.Expires.Before(time.Now().Add(12*time.Minute)) {
		t.Fatal("invalid private read-only credentials")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("private proof key generation")
	}
	defer clear(key)
	verifier := VerifierProcess{Executable: os.Getenv("CSV_PRIVATE_VERIFIER_PATH"), BinarySHA: os.Getenv("CSV_PRIVATE_VERIFIER_SHA"), RunID: id, JobID: id, Key: key, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: credentials.AccessKeyID, SecretAccessKey: credentials.SecretAccessKey, SessionToken: credentials.SessionToken, CanExpire: true, Expires: credentials.Expires}, nil
	})}
	if privateExecutablePreflight(verifier.Executable, verifier.BinarySHA) != nil || privateExecutablePreflight(os.Getenv("CSV_PRIVATE_COORDINATOR_PATH"), os.Getenv("CSV_PRIVATE_COORDINATOR_SHA")) != nil {
		t.Fatal("immutable local artifacts preflight failed")
	}
	fixture, err := privateSmallFixture("join")
	if err != nil {
		t.Fatal("private fixture invalid")
	}
	run := PrivateAPIRun{ID: id, Until: until, Request: fixture.Request}
	cfg, err := awsenv.Load()
	if err != nil {
		t.Fatal("private AWS configuration invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err = NewPrivateUploadCoordinator(ctx, run, cfg, verifier); err != nil {
		t.Fatal("read-only coordinator constructor stage", privateFailureClass(err))
	}
	done, err := startPrivateUploadConsumer(ctx, run, verifier)
	if err != nil {
		t.Fatal("read-only coordinator child stage", privateFailureClass(err))
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("read-only coordinator child stop unconfirmed")
	}
	t.Log("PRIVATE_COORDINATOR_READ_ONLY_READY exact_identity=true immutable_verifier=true no_admission=true no_upload=true no_task_start=true")
}
