package csvcloud

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// NewPrivateUploadCoordinator is called only by the distinct operator-launched
// coordinator executable. STS must confirm the exact run-specific role/session;
// an API task role or broad operator session is rejected before data access.
func NewPrivateUploadCoordinator(ctx context.Context, run PrivateAPIRun, cfg aws.Config, verifier VerifierProcess) (PrivateUploadCoordinator, error) {
	if !opaque(run.ID) || run.Request.Validate() != nil || !privatePartPlanValid(run) || run.Until <= time.Now().Unix() || run.Until > time.Now().Add(2*time.Hour).Unix() || verifier.RunID != run.ID || verifier.JobID != run.ID {
		return PrivateUploadCoordinator{}, ErrInvalid
	}
	if len(verifier.Key) != ed25519.PrivateKeySize || verifier.Credentials == nil {
		return PrivateUploadCoordinator{}, ErrInvalid
	}
	binary, e := verifier.openBinary()
	if e != nil {
		return PrivateUploadCoordinator{}, e
	}
	binary.Close()
	readonly, e := verifier.Credentials.Retrieve(ctx)
	if e != nil || readonly.SessionToken == "" || !readonly.CanExpire || readonly.Expires.Before(time.Now().Add(11*time.Minute)) {
		return PrivateUploadCoordinator{}, ErrInvalid
	}
	if err := privateCoordinatorIdentity(ctx, cfg, run.ID); err != nil {
		return PrivateUploadCoordinator{}, err
	}
	if run.Request.Version == 2 {
		client, ok := cfg.HTTPClient.(*http.Client)
		if !ok {
			return PrivateUploadCoordinator{}, ErrInvalid
		}
		copy := *client
		copy.Timeout = 180 * time.Second
		cfg.HTTPClient = &copy
	}
	a, e := clients(cfg)
	if e != nil {
		return PrivateUploadCoordinator{}, e
	}
	repo := Repository{Client: a.Dynamo, Table: "utils-bot-csv-private-" + run.ID[:16], Gate: Gate{Enabled: true}}
	objects := Storage{Client: a.S3, Presigner: a.Parts, Bucket: "utils-csv-999999999999-" + run.ID[:24], Account: "999999999999", Gate: Gate{Enabled: true}}
	b := &PrivateRunBackend{RunID: run.ID, Until: run.Until, SyntheticOnly: true, Request: run.Request, Parts: run.Parts, Repo: repo, Objects: objects, Queue: Queue{Client: a.SQS, URL: "https://sqs.us-east-2.amazonaws.com/999999999999/" + repo.Table, Repo: repo, Gate: Gate{Enabled: true}}}
	fence := RunFence{Repo: repo, Storage: objects, Control: a.S3, RunID: run.ID, JobID: run.ID, PolicyHash: AbsentBucketPolicyHash, SyntheticOnly: true, VerifyBucket: func(ctx context.Context) error { return verifier.VerifyBucket(ctx, objects.Bucket, objects.Account) }, StopWriters: func(ctx context.Context, j Job) error {
		// The versioned fence commits before this callback. Neither Runner nor the
		// API can subsequently create dispatch/upload intent using the old version.
		current, e := repo.Get(ctx, j.ID)
		if e != nil || current == nil || current.Artifact != "DELETING" || current.Dispatch != nil || current.TransferStarted || current.Version != j.Version || time.Now().Unix() < current.UploadUntil+90 {
			return ErrCleanup
		}
		broker, e := repo.get(ctx, "BROKER/"+run.ID)
		if e != nil || len(broker) != 0 {
			return ErrCleanup
		}
		return nil
	}}
	cleanup := Cleanup{Repo: repo, Writers: fence, Objects: fence, Gate: Gate{Enabled: true}}
	return PrivateUploadCoordinator{Backend: b, Retire: func(ctx context.Context, j Job) error { return cleanup.Complete(ctx, j.ID) }}, nil
}
func privateCoordinatorIdentity(ctx context.Context, cfg aws.Config, run string) error {
	if !opaque(run) || cfg.Region != Region || cfg.BaseEndpoint != nil || cfg.HTTPClient == nil || cfg.Credentials == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	payload := "Action=GetCallerIdentity&Version=2011-06-15"
	req, e := http.NewRequestWithContext(ctx, "POST", "https://sts.us-east-2.amazonaws.com/", strings.NewReader(payload))
	if e != nil {
		return ErrInvalid
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	credential, e := cfg.Credentials.Retrieve(ctx)
	if e != nil {
		return ErrUnknown
	}
	// Only short-lived role credentials can enter this executable.
	if credential.SessionToken == "" {
		return ErrInvalid
	}
	h := sha256.Sum256([]byte(payload))
	if v4.NewSigner().SignHTTP(ctx, credential, req, hex.EncodeToString(h[:]), "sts", Region, time.Now()) != nil {
		return ErrUnknown
	}
	resp, e := cfg.HTTPClient.Do(req)
	if e != nil {
		return ErrUnknown
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if e != nil || len(raw) > 8192 || resp.StatusCode != 200 {
		return ErrUnknown
	}
	var out struct {
		XMLName xml.Name
		Result  struct{ Arn, Account string } `xml:"GetCallerIdentityResult"`
	}
	if xml.Unmarshal(raw, &out) != nil || out.XMLName.Local != "GetCallerIdentityResponse" || out.Result.Account != "999999999999" || out.Result.Arn != "arn:aws:sts::999999999999:assumed-role/AgentPdfMock-CsvUpload-"+run[:16]+"/csv-upload-"+run[:16] {
		return ErrIntegrity
	}
	return nil
}
