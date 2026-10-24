package csvcloud

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPrivateCoordinatorConsumesSignalOnce(t *testing.T) {
	f := newPrivateBackendFixture(t)
	c := PrivateUploadCoordinator{Backend: f.b}
	if done, e := c.Step(ctx); e != nil || done {
		t.Fatal("absent job", done, e)
	}
	if _, e := f.b.Begin(ctx, f.b.Request); e != nil {
		t.Fatal(e)
	}
	if done, e := c.Step(ctx); e != nil || done || f.completes != 0 || f.queue.calls != 0 {
		t.Fatal("processed without signal", e)
	}
	if e := f.b.Complete(ctx, f.b.RunID); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if done, e := c.Step(ctx); e != nil || !done {
			t.Fatal(done, e)
		}
	}
	if f.completes != 1 || f.queue.calls != 1 {
		t.Fatal("replayed completion or publish")
	}
}
func TestPrivateCoordinatorUnknownCreateRetainsCapacityUntilProof(t *testing.T) {
	for _, lost := range []string{"create-reply", "database-update"} {
		t.Run(lost, func(t *testing.T) {
			f := newPrivateBackendFixture(t)
			if lost == "create-reply" {
				f.lostCreate = true
			} else {
				wrapper := &privateUploadDBFault{DynamoAPI: f.db}
				f.b.Repo.Client = wrapper
				f.b.Queue.Repo = f.b.Repo
			}
			if _, err := f.b.Begin(ctx, f.b.Request); err == nil {
				t.Fatal("unknown upload reply accepted")
			}
			j := readJob(t, f.b.Repo, f.b.RunID)
			var err error
			if _, err = f.b.Begin(ctx, f.b.Request); err == nil || f.creates != 1 {
				t.Fatal("ambiguous create repeated", err)
			}
			if err = f.b.Complete(ctx, f.b.RunID); err != nil {
				t.Fatal(err)
			}
			now := fixtureTime
			f.b.Now = func() time.Time { return now }
			proof := false
			retireCalls := 0
			c := PrivateUploadCoordinator{Backend: f.b, Retire: func(ctx context.Context, j Job) error {
				retireCalls++
				if !proof {
					return ErrCleanup
				}
				// This callback models the existing RunFence/Cleanup contract, whose cloud
				// implementation requires independent bucket-absence convergence.
				return f.b.Repo.erased(ctx, j)
			}}
			if done, e := c.Step(ctx); e != nil || done || f.queue.calls != 0 {
				t.Fatal("uncertain create dispatched", e)
			}
			now = time.Unix(j.UploadUntil, 0)
			if done, e := c.Step(ctx); e != nil || done || retireCalls != 0 {
				t.Fatal("retired before request/grant window", e)
			}
			if readJob(t, f.b.Repo, f.b.RunID).Artifact != "DELETING" {
				t.Fatal("missing durable retirement fence")
			}
			fencedVersion := readJob(t, f.b.Repo, f.b.RunID).Version
			for range 3 {
				if done, e := c.Step(ctx); e != nil || done {
					t.Fatal("stable retirement wait", e)
				}
			}
			if readJob(t, f.b.Repo, f.b.RunID).Version != fencedVersion {
				t.Fatal("DELETING version churn")
			}
			now = now.Add(91 * time.Second)
			if _, e := c.Step(ctx); e != ErrCleanup {
				t.Fatal("missing absence proof accepted", e)
			}
			cap, e := f.b.Repo.get(ctx, "CAPACITY")
			if e != nil || avsPrivate(cap["used"]) != "1" {
				t.Fatal("capacity released without proof")
			}
			proof = true
			if done, e := c.Step(ctx); e != nil || !done {
				t.Fatal("proved cleanup failed", done, e)
			}
			if f.creates != 1 || f.queue.calls != 0 || readJob(t, f.b.Repo, f.b.RunID).Artifact != "ERASED" {
				t.Fatal("unsafe recovery")
			}
		})
	}
}

func TestPrivateUploadReadyGate(t *testing.T) {
	run := ID()
	for _, line := range []string{"", "CSV_UPLOAD_READY " + ID() + "\n", "CSV_UPLOAD_READY " + run, strings.Repeat("x", 129)} {
		if e := awaitPrivateUploadReady(ctx, strings.NewReader(line), run); e == nil {
			t.Fatal("invalid readiness accepted")
		}
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	c, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- awaitPrivateUploadReady(c, reader, run) }()
	select {
	case <-done:
		t.Fatal("process launch treated as ready")
	default:
	}
	cancel()
	if <-done == nil {
		t.Fatal("cancellation admitted")
	}
	reader.Close()
	if e := awaitPrivateUploadReady(ctx, strings.NewReader("CSV_UPLOAD_READY "+run+"\n"), run); e != nil {
		t.Fatal(e)
	}
}

func TestPrivateCoordinatorRejectsWrongRoleBeforeDataAccess(t *testing.T) {
	run := ID()
	for _, principal := range []string{"arn:aws:sts::818416606421:assumed-role/AgentPdfMock-CsvUpload-" + run[:16] + "/csv-upload-" + run[:16], "arn:aws:sts::818416606421:assumed-role/AgentPdfMock-TaskRole/task", "arn:aws:sts::818416606421:assumed-role/AWSReservedSSO_LocalCLIAccess_452e4a519811dc0f/super-read-only", "arn:aws:sts::818416606421:assumed-role/AgentPdfMock-CsvUpload-" + run[:16] + "/wrong-session"} {
		calls := 0
		cfg := sdkConfig(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Host != "sts.us-east-2.amazonaws.com" {
				t.Fatal("data access before identity preflight")
			}
			return response(200, "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>818416606421</Account><Arn>"+principal+"</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>", nil), nil
		})
		cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "synthetic", SessionToken: "synthetic"}, nil
		})
		err := privateCoordinatorIdentity(ctx, cfg, run)
		if (err == nil) != (strings.Contains(principal, "/csv-upload-"+run[:16])) || calls != 1 {
			t.Fatal("role preflight", err)
		}
	}
}

// Fail the OPEN update after S3 has accepted creation, before the DB commit.
// This exercises the real adapter control flow rather than constructing rows.
type privateUploadDBFault struct {
	DynamoAPI
	fired  bool
	commit bool
}

func (f *privateUploadDBFault) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, opt ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	for _, item := range in.TransactItems {
		if p := item.Put; p != nil && !f.fired && strings.HasPrefix(avsPrivate(p.Item["pk"]), "API_UPLOAD/") && avsPrivate(p.Item["version"]) == "2" {
			f.fired = true
			if f.commit {
				_, _ = f.DynamoAPI.TransactWriteItems(ctx, in, opt...)
			}
			return nil, ErrUnknown
		}
	}
	return f.DynamoAPI.TransactWriteItems(ctx, in, opt...)
}
func TestPrivateCoordinatorCommittedUploadUpdateReplyReconcilesOriginal(t *testing.T) {
	f := newPrivateBackendFixture(t)
	wrapper := &privateUploadDBFault{DynamoAPI: f.db, commit: true}
	f.b.Repo.Client = wrapper
	f.b.Queue.Repo = f.b.Repo
	if _, err := f.b.Begin(ctx, f.b.Request); err == nil {
		t.Fatal("lost reply accepted")
	}
	admission, err := f.b.Begin(ctx, f.b.Request)
	if err != nil || len(admission.Parts) != 1 || f.creates != 1 || !wrapper.fired || f.queue.calls != 0 {
		t.Fatal("original upload not reconciled", err)
	}
}
