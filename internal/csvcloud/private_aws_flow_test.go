package csvcloud

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	st "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"
	tabular "pdfservice/internal/csvtabular"
	"pdfservice/internal/csvwire"
	"pdfservice/internal/jsonwire"
)

func privateJoinFixture() (csvwire.Request, map[string][]byte, []byte) {
	inputs := map[string][]byte{}
	values := map[string][]string{}
	for _, slot := range []string{"left", "right"} {
		rows := make([]string, 1024)
		header := "key," + slot + "\n"
		size := len(header)
		for i := range rows {
			rows[i] = strings.Repeat(slot[:1], 496)
			size += len(strconv.Itoa(i)) + 1 + len(rows[i]) + 1
		}
		rows[len(rows)-1] += strings.Repeat(slot[:1], (1<<19)-size)
		var b bytes.Buffer
		b.WriteString(header)
		for i, v := range rows {
			fmt.Fprintf(&b, "%d,%s\n", i, v)
		}
		inputs[slot] = b.Bytes()
		values[slot] = rows
	}
	var expected bytes.Buffer
	expected.WriteString("key,left,right\n")
	for i, v := range values["left"] {
		fmt.Fprintf(&expected, "%d,%s,%s\n", i, v, values["right"][i])
	}
	options, _ := tabular.CanonicalOptions("join", json.RawMessage(`{"left_key_columns":["key"],"right_key_columns":["key"],"type":"inner"}`))
	q := csvwire.Request{Version: 1, Operation: "join", Options: options}
	for _, slot := range []string{"left", "right"} {
		q.Files = append(q.Files, csvwire.File{Slot: slot, Bytes: int64(len(inputs[slot])), SHA256: Hash(inputs[slot])})
	}
	return q, inputs, expected.Bytes()
}
func TestPrivateJoinFixtureIndependentOracle(t *testing.T) {
	q, in, want := privateJoinFixture()
	if q.Validate() != nil || len(in["left"])+len(in["right"]) != 1<<20 {
		t.Fatal("fixture bounds")
	}
	result, e := tabular.Execute(q.Operation, q.Options, in)
	if e != nil {
		t.Fatal(e)
	}
	// The oracle constructs planted pairs directly, without the join engine.
	var encoded bytes.Buffer
	writer := csv.NewWriter(&encoded)
	e = writer.Write(result.Columns)
	if e == nil {
		e = writer.WriteAll(result.Rows)
	}
	writer.Flush()
	got := encoded.Bytes()
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("independent fixture oracle")
	}
}
func privateIdentities(now time.Time) (csvwire.Bootstrap, csvwire.Bootstrap, error) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return csvwire.Bootstrap{}, csvwire.Bootstrap{}, e
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-only"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(15 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return csvwire.Bootstrap{}, csvwire.Bootstrap{}, e
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	makeLeaf := func(client bool) (csvwire.Bootstrap, []byte, error) {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return csvwire.Bootstrap{}, nil, e
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"csv-worker"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if client {
			leaf.SerialNumber = big.NewInt(3)
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, ca, &k.PublicKey, caKey)
		if e != nil {
			return csvwire.Bootstrap{}, nil, e
		}
		key, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			return csvwire.Bootstrap{}, nil, e
		}
		return csvwire.Bootstrap{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key})), ClientCA: caPEM}, raw, nil
	}
	server, sder, e := makeLeaf(false)
	if e != nil {
		return server, csvwire.Bootstrap{}, e
	}
	client, cder, e := makeLeaf(true)
	server.PeerSHA256 = Hash(cder)
	client.PeerSHA256 = Hash(sder)
	return server, client, e
}

type privateCountingECS struct {
	*ecs.Client
	starts         int
	errorCode      string
	failureReasons []string
}

func (c *privateCountingECS) RunTask(ctx context.Context, in *ecs.RunTaskInput, opts ...func(*ecs.Options)) (*ecs.RunTaskOutput, error) {
	c.starts++
	out, err := c.Client.RunTask(ctx, in, opts...)
	var api smithy.APIError
	if errors.As(err, &api) {
		c.errorCode = api.ErrorCode()
	}
	if out != nil {
		for _, f := range out.Failures {
			c.failureReasons = append(c.failureReasons, aws.ToString(f.Reason))
		}
	}
	return out, err
}

func privateClusterReady(out *ecs.DescribeClustersOutput, arn string) bool {
	if out == nil || len(out.Failures) != 0 || len(out.Clusters) != 1 {
		return false
	}
	c := out.Clusters[0]
	return aws.ToString(c.ClusterArn) == arn && aws.ToString(c.Status) == "ACTIVE" &&
		c.RunningTasksCount == 0 && c.PendingTasksCount == 0 && c.ActiveServicesCount == 0
}

func TestPrivateClusterPreflightRejectsInactiveMissingAndOccupied(t *testing.T) {
	arn := "arn:aws:ecs:us-east-2:818416606421:cluster/utils-bot-csv-trial"
	good := et.Cluster{ClusterArn: aws.String(arn), Status: aws.String("ACTIVE")}
	if !privateClusterReady(&ecs.DescribeClustersOutput{Clusters: []et.Cluster{good}}, arn) {
		t.Fatal("empty active isolated cluster rejected")
	}
	for _, mode := range []string{"inactive", "missing", "foreign", "running", "pending", "service", "failure", "multiple"} {
		c := good
		out := &ecs.DescribeClustersOutput{}
		switch mode {
		case "inactive":
			c.Status = aws.String("INACTIVE")
		case "foreign":
			c.ClusterArn = aws.String("arn:aws:ecs:us-east-2:818416606421:cluster/agent-pdf-mock")
		case "running":
			c.RunningTasksCount = 1
		case "pending":
			c.PendingTasksCount = 1
		case "service":
			c.ActiveServicesCount = 1
		case "failure":
			out.Failures = []et.Failure{{Reason: aws.String("MISSING")}}
		}
		if mode != "missing" {
			out.Clusters = []et.Cluster{c}
		}
		if mode == "multiple" {
			out.Clusters = append(out.Clusters, good)
		}
		if privateClusterReady(out, arn) {
			t.Fatal("unsafe preflight accepted", mode)
		}
	}
}

// TestPrivateAWSFlow uses only pre-created isolated resources. IAM/trust creation
// is deliberately outside this test. A private operator acknowledgement follows
// independent exact-worker lifecycle-policy readback, before broker dispatch.
func TestPrivateAWSFlow(t *testing.T) {
	c, cfg := privateAWSInput(t, "flow")
	raw, e := os.ReadFile(c.StatePath)
	if e != nil {
		t.Fatal("registration state missing")
	}
	var state privateAWSState
	if jsonwire.Decode(raw, &state, 16<<10) != nil || state.Config != c {
		t.Fatal("registration state mismatch")
	}
	verifierPath := os.Getenv("CSV_PRIVATE_VERIFIER_PATH")
	verifierSHA := os.Getenv("CSV_PRIVATE_VERIFIER_SHA")
	var credential struct {
		AccessKeyID, SecretAccessKey, SessionToken string
		Expires                                    time.Time
	}
	if jsonwire.Decode([]byte(os.Getenv("CSV_PRIVATE_VERIFIER_CREDENTIALS")), &credential, 8192) != nil || credential.Expires.Before(time.Now().Add(12*time.Minute)) {
		t.Fatal("short-lived verifier credentials missing")
	}
	if _, e := os.Lstat(c.StatePath + ".attempt"); !os.IsNotExist(e) {
		t.Fatal("one-shot flow already attempted")
	}
	a, e := clients(cfg)
	if e != nil {
		t.Fatal("private clients")
	}
	repo := Repository{Client: a.Dynamo, Table: "utils-bot-csv-private-" + c.RunID[:16], Gate: Gate{Enabled: true}}
	storage := Storage{Client: a.S3, Presigner: a.Parts, Bucket: "utils-csv-818416606421-" + c.RunID[:24], Account: "818416606421", Gate: Gate{Enabled: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	// Preflight before even the local one-shot claim. A missing cluster does
	// not create a reservation, secret, upload or task definition.
	requirePrivateAWSCluster(t, ctx, a.ECS)
	claim, e := os.OpenFile(c.StatePath+".attempt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal("one-shot local claim")
	}
	claim.Close()
	// Validate provider defaults before any upload or task start.
	if (RunFence{Storage: storage, Control: a.S3, PolicyHash: AbsentBucketPolicyHash}).checkBucket(ctx) != nil {
		t.Fatal("trial bucket protections differ")
	}
	q, input, expected := privateJoinFixture()
	server, identity, e := privateIdentities(time.Now())
	if e != nil {
		t.Fatal("fixture TLS")
	}
	_, signingKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("proof key")
	}
	// No AWS credentials enter this checkpoint; it permits supervised recovery.
	checkpoint := struct {
		State          privateAWSState
		ProofKey       []byte
		Server, Client csvwire.Bootstrap
		Control        ControllerConfig
	}{State: state, ProofKey: signingKey, Server: server, Client: identity}
	checkpointRaw, _ := json.Marshal(checkpoint)
	if os.WriteFile(c.StatePath+".recovery", checkpointRaw, 0600) != nil {
		t.Fatal("private recovery checkpoint")
	}
	now := time.Now()
	plan := RunPlan{RunID: c.RunID, JobID: c.RunID, Account: storage.Account, Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, WorkerImage: c.WorkerImage, BrokerImage: c.BrokerImage, Created: now.Unix(), Until: now.Add(10 * time.Minute).Unix(), ResourcesUntil: c.ResourcesUntil, ReservedMicroUSD: 10_000_000, SyntheticOnly: true}
	if plan.Reserve(ctx, repo, now) != nil {
		t.Fatal("durable one-shot reservation")
	}
	job := Job{ID: c.RunID, IntentBinding: q.Binding(), Owner: "0x1111111111111111111111111111111111111111", AdmissionNonceHash: ID(), IdempotencyHash: ID(), RecoveryVerifier: ID(), CapabilityVerifier: ID(), Version: 1, Artifact: "UPLOAD_INCOMPLETE", Financial: "UNPAID", UploadUntil: now.Add(5 * time.Minute).Unix()}
	for _, f := range q.Files {
		job.Inputs = append(job.Inputs, Object{JobID: job.ID, ID: ID(), Slot: f.Slot, Bytes: f.Bytes, SHA256: f.SHA256})
	}
	if repo.Create(ctx, job, 1) != nil {
		t.Fatal("job/capacity reservation")
	}
	for _, o := range job.Inputs {
		upload := Upload{Object: o, Parts: []Part{{Number: 1, Bytes: o.Bytes, SHA256: o.SHA256}}, Expires: job.UploadUntil}
		// Persist the CREATING key before the non-retried create call.
		if repo.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(repo.Table), Item: map[string]d.AttributeValue{"pk": str("UPLOAD/" + o.ID), "state": str("CREATING"), "key": str(o.key(false))}, ConditionExpression: aws.String("attribute_not_exists(pk)")}}}) != nil {
			t.Fatal("upload reservation")
		}
		upload, e = storage.Begin(ctx, upload)
		if e != nil {
			t.Fatal("upload create uncertain")
		}
		saved, _ := json.Marshal(upload)
		if os.WriteFile(c.StatePath+".upload-"+o.Slot, saved, 0600) != nil {
			t.Fatal("upload checkpoint")
		}
		grant, e := storage.Grant(ctx, upload, 1, time.Now())
		if e != nil {
			t.Fatal("part grant")
		}
		request, _ := http.NewRequestWithContext(ctx, "PUT", grant.URL, bytes.NewReader(input[o.Slot]))
		request.ContentLength = o.Bytes
		request.Header = http.Header(grant.Headers).Clone()
		response, e := cfg.HTTPClient.Do(request)
		if e != nil {
			t.Fatal("part transfer uncertain")
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("part transfer rejected", response.StatusCode)
		}
		if _, e = storage.Complete(ctx, upload); e != nil {
			t.Fatal("multipart completion uncertain", e)
		}
	}
	if (Artifacts{Repo: repo, Inputs: storage, Gate: Gate{Enabled: true}}).AcceptUploads(ctx, job.ID) != nil {
		t.Fatal("whole input verification")
	}
	t.Log("PRIVATE_UPLOADS_VERIFIED bytes=1048576 files=2")
	jobPtr, e := repo.Get(ctx, job.ID)
	if e != nil || jobPtr == nil {
		t.Fatal("job readback")
	}
	job, e = repo.Queue(ctx, *jobPtr, ID(), 10_000_000, 10_000_000)
	if e != nil {
		t.Fatal("cost/outbox reservation")
	}
	queue := Queue{Client: a.SQS, URL: "https://sqs.us-east-2.amazonaws.com/818416606421/" + repo.Table, Repo: repo, Gate: Gate{Enabled: true}}
	if queue.Publish(ctx, job.ID) != nil || queue.Publish(ctx, job.ID) != ErrConflict {
		t.Fatal("one-shot queue publish")
	}
	messages, e := a.SQS.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: aws.String(queue.URL), MaxNumberOfMessages: 1, WaitTimeSeconds: 10})
	if e != nil || len(messages.Messages) != 1 {
		t.Fatal("private queue receive")
	}
	message, e := DecodeMessage([]byte(aws.ToString(messages.Messages[0].Body)))
	if e != nil {
		t.Fatal("queue binding")
	}
	if _, e = a.SQS.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: aws.String(queue.URL), ReceiptHandle: messages.Messages[0].ReceiptHandle}); e != nil {
		t.Fatal("private queue claim")
	}
	reaper := Reaper{Repo: repo, RunID: plan.RunID, JobID: job.ID}
	if reaper.Schedule(ctx, time.Now().Add(2*time.Minute).Unix()) != nil {
		t.Fatal("durable recovery schedule before dispatch")
	}
	t.Log("PRIVATE_RECOVERY_ARMED before_dispatch=true")
	secrets := ssm.NewFromConfig(cfg)
	tlsRaw, _ := json.Marshal(server)
	if _, e = secrets.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String("/utils-bot/csv-private/" + c.RunID + "/tls"), Value: aws.String(string(tlsRaw)), Type: st.ParameterTypeSecureString, Tier: st.ParameterTierStandard, Overwrite: aws.Bool(false)}); e != nil {
		t.Fatal("private TLS parameter write failed")
	}
	counted := &privateCountingECS{Client: a.ECS}
	review := privateAWSReview(c)
	runner := Runner{Wire: &review, Client: counted, Repo: repo, Gate: Gate{Enabled: true, Dispatch: true}, Cluster: "arn:aws:ecs:us-east-2:818416606421:cluster/utils-bot-csv-trial", Definition: state.WorkerDefinition, Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, Container: "transport", IsolationReview: state.WorkerHash}
	startError := plan.StartWorker(ctx, runner, message, time.Now())
	if startError != nil {
		t.Fatalf("worker start uncertain; preserve original attempt: %v api_code=%s failure_reasons=%q", startError, counted.errorCode, counted.failureReasons)
	}
	jobPtr, e = repo.Get(ctx, job.ID)
	if e != nil || jobPtr == nil || jobPtr.Dispatch == nil || jobPtr.Dispatch.TaskARN == "" {
		t.Fatal("original worker ARN missing")
	}
	if plan.StartWorker(ctx, runner, message, time.Now()) != nil || counted.starts != 1 {
		t.Fatal("duplicate worker dispatch")
	}
	worker := StoppedObserver{Cluster: runner.Cluster, TaskARN: jobPtr.Dispatch.TaskARN, Definition: state.WorkerDefinition, Group: "csv-" + jobPtr.Dispatch.Token, StartedBy: jobPtr.Dispatch.Token[:32]}
	control := ControllerConfig{RunID: plan.RunID, JobID: job.ID, Account: storage.Account, Table: repo.Table, Bucket: storage.Bucket, PolicyHash: AbsentBucketPolicyHash, Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, SyntheticOnly: true, Worker: worker, Broker: StoppedObserver{Cluster: runner.Cluster, Definition: state.BrokerDefinition, Group: "csv-broker-" + plan.RunID, StartedBy: plan.RunID[:32]}}
	verifier := VerifierProcess{Executable: verifierPath, BinarySHA: verifierSHA, RunID: plan.RunID, JobID: job.ID, Key: signingKey, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey, SessionToken: credential.SessionToken, CanExpire: true, Expires: credential.Expires}, nil
	})}
	checkpoint.Control = control
	checkpointRaw, _ = json.Marshal(checkpoint)
	if os.WriteFile(c.StatePath+".recovery", checkpointRaw, 0600) != nil {
		t.Fatal("original task checkpoint")
	}
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() {
		sawResult := false
		lateVerified := false
		for ctx.Err() == nil {
			mu.Lock()
			scope := control
			mu.Unlock()
			controller, e := AssembleController(ctx, scope, cfg, verifier)
			if e == nil {
				_ = controller.FulfilNetwork(ctx)
				_ = controller.FinalizeCandidate(ctx)
				current, err := repo.Get(ctx, job.ID)
				if err == nil && current != nil && current.Artifact == "RESULT_PREPARED" {
					if current.Financial != "AWAITING_PAYMENT" || current.Settlement != nil || !current.WorkerStopped || current.Result == nil || current.Result.LogicalSHA256 != Hash(expected) || current.Result.Rows != 1024 {
						done <- ErrIntegrity
						return
					}
					if _, err = storage.VerifyResult(ctx, *current.Result); err != nil {
						done <- err
						return
					}
					if _, err = storage.ReadPaidRange(ctx, nil, time.Now().Unix()); err != ErrConflict {
						done <- ErrIntegrity
						return
					}
					if _, err = repo.ReserveDownload(ctx, *current, ID(), 0, 0, time.Now().Unix()); err != ErrConflict {
						done <- ErrIntegrity
						return
					}
					sawResult = true
					if controller.FinishSynthetic(ctx) != nil {
						done <- ErrConflict
						return
					}
				}
				var late *privateLatePut
				schedule, readErr := controller.Reaper.read(ctx)
				if sawResult && !lateVerified && readErr == nil && schedule.State == "PENDING" && time.Now().Unix() >= schedule.Due {
					late, e = beginPrivateLatePut(ctx, a, storage, job.ID)
					if e != nil {
						done <- ErrCleanup
						return
					}
				}
				_ = controller.Reaper.Tick(ctx)
				if late != nil {
					capacity, _ := repo.get(ctx, "CAPACITY")
					if avs(capacity["used"]) != "1" {
						late.release()
						done <- ErrIntegrity
						return
					}
					fence, _ := repo.get(ctx, "FENCE/"+plan.RunID)
					deleted := avs(fence["phase"]) == "DELETED"
					late.release()
					select {
					case result := <-late.done:
						if result != 200 && result != 404 {
							done <- ErrCleanup
							return
						}
						// A held request can return 200 after deletion. The safety
						// contract is independently rejected object access,
						// rejected fresh writes/replay, and converged bucket
						// absence before Cleanup releases capacity.
						if deleted && late.accessBlocked(ctx, a, storage) != nil {
							done <- ErrIntegrity
							return
						}
						lateVerified = deleted
						t.Logf("PRIVATE_LATE_PUT after_delete_ack=%t status=%d capacity_held=true", deleted, result)
					case <-ctx.Done():
						done <- ErrCleanup
						return
					}
				}
				current, _ = repo.Get(ctx, job.ID)
				if current != nil && current.Artifact == "ERASED" {
					if !sawResult || !lateVerified {
						done <- ErrUnknown
					} else {
						done <- nil
					}
					return
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
		done <- ErrCleanup
	}()
	t.Logf("PRIVATE_WORKER_BOUND %s", worker.TaskARN)
	// Parent operator verifies and installs only exact-original-worker lifecycle
	// permission; no IAM policy document or credential is written by this test.
	ready := filepath.Join(filepath.Dir(c.StatePath), "lifecycle-ready")
	until := time.Now().Add(60 * time.Second)
	for time.Now().Before(until) {
		raw, e := os.ReadFile(ready)
		if e == nil && string(raw) == c.RunID+" "+worker.TaskARN {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	readyRaw, _ := os.ReadFile(ready)
	if string(readyRaw) != c.RunID+" "+worker.TaskARN {
		t.Error("exact-worker lifecycle acknowledgement missing")
	} else {
		waitUntil := time.Now().Add(60 * time.Second)
		running := false
		for time.Now().Before(waitUntil) {
			status, e := a.ECS.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(runner.Cluster), Tasks: []string{worker.TaskARN}})
			if e == nil && len(status.Tasks) == 1 {
				if aws.ToString(status.Tasks[0].LastStatus) == "STOPPED" {
					break
				}
				if aws.ToString(status.Tasks[0].LastStatus) == "RUNNING" {
					running = true
					break
				}
			}
			time.Sleep(time.Second)
		}
		if !running {
			t.Error("worker did not reach RUNNING")
		} else {
			bootstrap := BrokerBootstrap{RunID: plan.RunID, JobID: job.ID, Account: storage.Account, Table: repo.Table, Bucket: storage.Bucket, Cluster: runner.Cluster, Definition: state.WorkerDefinition, Subnet: privateTrialSubnet, Prefix: "10.88.0.0/24", Until: plan.Until, Review: review, Request: q, Identity: identity, NetworkPublicKey: base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey))}
			encoded, _ := json.Marshal(bootstrap)
			if _, e = DecodeBroker(encoded, time.Now()); e != nil {
				t.Error("broker bootstrap binding")
			} else if _, e = secrets.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String("/utils-bot/csv-private/" + c.RunID + "/broker"), Value: aws.String(string(encoded)), Type: st.ParameterTypeSecureString, Tier: st.ParameterTierAdvanced, Overwrite: aws.Bool(false)}); e != nil {
				t.Error("broker parameter write")
			} else {
				arn, e := plan.StartBroker(ctx, repo, counted, BrokerReview{Worker: review, Image: c.BrokerImage}, state.BrokerDefinition, state.BrokerHash, privateTrialSubnet, privateTrialSecurityGroup, time.Now())
				if e != nil {
					t.Error("broker start uncertain; no retry", e)
				} else {
					mu.Lock()
					control.Broker.TaskARN = arn
					mu.Unlock()
					checkpoint.Control = control
					checkpointRaw, _ = json.Marshal(checkpoint)
					if os.WriteFile(c.StatePath+".recovery", checkpointRaw, 0600) != nil {
						t.Error("original broker checkpoint")
					}
					t.Logf("PRIVATE_BROKER_BOUND %s", arn)
				}
			}
		}
	}
	outcome := <-done
	if outcome != nil {
		t.Fatal("private processing or cleanup unconfirmed", outcome)
	}
	capacity, e := repo.get(ctx, "CAPACITY")
	if e != nil || avs(capacity["used"]) != "0" || counted.starts != 2 {
		t.Fatal("capacity/one-attempt invariant")
	}
	t.Log("PRIVATE_FLOW_VERIFIED multipart, job, one-worker+broker, mTLS, independent ENI proof, gzip oracle, unpaid-download rejection, task/bucket erasure")
}

// Hold an already accepted synthetic PUT body across the deletion attempt. No
// URL, signature or body is logged. The only capability is this one owned key.
type privateLatePut struct {
	release func()
	done    chan int
	key     string
	replay  func() int
}

func (p *privateLatePut) accessBlocked(ctx context.Context, a AWSClients, storage Storage) error {
	out, err := a.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(storage.Bucket), Key: aws.String(p.key), ExpectedBucketOwner: aws.String(storage.Account)}, noS3Retry)
	if out != nil && out.Body != nil {
		out.Body.Close()
	}
	if !apiCode(err, "NoSuchBucket") {
		return ErrIntegrity
	}
	_, err = a.S3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(storage.Bucket), Key: aws.String(p.key), Body: bytes.NewReader([]byte("synthetic replay\n")), ExpectedBucketOwner: aws.String(storage.Account), ServerSideEncryption: "AES256", IfNoneMatch: aws.String("*")}, noS3Retry)
	if !apiCode(err, "NoSuchBucket") || p.replay() != 404 {
		return ErrIntegrity
	}
	return nil
}

func beginPrivateLatePut(ctx context.Context, a AWSClients, storage Storage, job string) (*privateLatePut, error) {
	payload := []byte("synthetic late result\n")
	key := "results/" + job + "/" + ID()
	signed, e := a.Parts.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(storage.Bucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(storage.Account), ContentLength: aws.Int64(int64(len(payload))), ChecksumSHA256: aws.String(checksum(Hash(payload))), IfNoneMatch: aws.String("*"), ServerSideEncryption: "AES256"}, func(o *s3.PresignOptions) { o.Expires = time.Minute })
	if e != nil {
		return nil, ErrCleanup
	}
	reader, writer := io.Pipe()
	release := make(chan struct{})
	ready := make(chan struct{})
	done := make(chan int, 1)
	var once sync.Once
	var readyOnce sync.Once
	releaseBody := func() { once.Do(func() { close(release) }) }
	go func() {
		select {
		case <-release:
			_, _ = writer.Write(payload)
			_ = writer.Close()
		case <-ctx.Done():
			_ = writer.CloseWithError(ctx.Err())
		}
	}()
	request, e := http.NewRequestWithContext(ctx, "PUT", signed.URL, reader)
	if e != nil {
		releaseBody()
		return nil, ErrCleanup
	}
	request.ContentLength = int64(len(payload))
	request.Header = signed.SignedHeader.Clone()
	request.Header.Set("Expect", "100-continue")
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{Got100Continue: func() { readyOnce.Do(func() { close(ready) }) }}))
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{ExpectContinueTimeout: 2 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go func() {
		response, e := client.Do(request)
		if e != nil {
			_ = reader.CloseWithError(e)
			done <- 0
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		status := response.StatusCode
		if status == 404 && !bytes.Contains(body, []byte("<Code>NoSuchBucket</Code>")) {
			status = 0
		}
		done <- status
	}()
	select {
	case <-ready:
		replay := func() int {
			req, err := http.NewRequestWithContext(ctx, "PUT", signed.URL, bytes.NewReader(payload))
			if err != nil {
				return 0
			}
			req.Header = signed.SignedHeader.Clone()
			resp, err := client.Do(req)
			if err != nil {
				return 0
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			if resp.StatusCode != 404 || !bytes.Contains(body, []byte("<Code>NoSuchBucket</Code>")) {
				return 0
			}
			return 404
		}
		return &privateLatePut{release: releaseBody, done: done, key: key, replay: replay}, nil
	case <-time.After(5 * time.Second):
		releaseBody()
		return nil, ErrCleanup
	case <-ctx.Done():
		releaseBody()
		return nil, ErrCleanup
	}
}

func TestPrivateBootstrapFitsSecretBoundsAndAuthenticatesClient(t *testing.T) {
	now := fixtureTime
	server, client, e := privateIdentities(now)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(server)
	if len(raw) > 4096 {
		t.Fatal("transport secret exceeds standard parameter limit")
	}
	if _, e = csvwire.ServerTLS(raw, now); e != nil {
		t.Fatal("server identity", e)
	}
	cfg, e := csvwire.ClientTLS(client, now)
	if e != nil || len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != csvwire.Protocol {
		t.Fatal("client identity")
	}
	c := privateAWSConfig{RunID: strings.Repeat("a", 64), WorkerImage: "818416606421.dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-private@sha256:" + strings.Repeat("b", 64)}
	q, _, _ := privateJoinFixture()
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b := BrokerBootstrap{RunID: c.RunID, JobID: c.RunID, Account: "818416606421", Table: "utils-bot-csv-private-" + c.RunID[:16], Bucket: "utils-csv-818416606421-" + c.RunID[:24], Cluster: "arn:aws:ecs:us-east-2:818416606421:cluster/utils-bot-csv-trial", Definition: "arn:aws:ecs:us-east-2:818416606421:task-definition/utils-bot-csv-private-" + c.RunID[:16] + "-worker:1", Subnet: privateTrialSubnet, Prefix: "10.88.0.0/24", Until: now.Add(10 * time.Minute).Unix(), Review: privateAWSReview(c), Request: q, Identity: client, NetworkPublicKey: base64.StdEncoding.EncodeToString(pub)}
	encoded, _ := json.Marshal(b)
	if len(encoded) > 8192 {
		t.Fatal("broker secret exceeds advanced parameter limit")
	}
	if _, e = DecodeBroker(encoded, now); e != nil {
		t.Fatal("valid private bootstrap rejected")
	}
	// The broker accepts the same four bounded tools as the private HTTP and
	// wire contracts. The one-shot AWS fixture remains a fixed 1 MiB join.
	for op, options := range map[string]string{
		"dedupe":    `{"key_columns":["id"],"keep":"first"}`,
		"aggregate": `{"group_columns":["id"],"metrics":[{"name":"n","op":"count_rows"}]}`,
		"transform": `{"column":"id","op":"upper"}`,
	} {
		t.Run(op, func(t *testing.T) {
			candidate := b
			canon, err := tabular.CanonicalOptions(op, json.RawMessage(options))
			if err != nil {
				t.Fatal(err)
			}
			candidate.Request = csvwire.Request{Version: 1, Operation: op, Options: canon, Files: []csvwire.File{{Slot: "file", Bytes: csvwire.MaxInput, SHA256: ID()}}}
			encoded, _ := json.Marshal(candidate)
			if _, err := DecodeBroker(encoded, now); err != nil {
				t.Fatal("bounded tool rejected", err)
			}
			candidate.Request.Files[0].Bytes++
			encoded, _ = json.Marshal(candidate)
			if _, err := DecodeBroker(encoded, now); err == nil {
				t.Fatal("worker byte limit bypassed")
			}
		})
	}

	worker := PrivateWorker{Review: &b.Review, Client: &lifecycleStub{}, Verifier: &networkStub{}, Cluster: b.Cluster, Definition: b.Definition, Subnet: b.Subnet, Prefix: netip.MustParsePrefix(b.Prefix), TLS: cfg, Gate: Gate{Enabled: true}}
	dispatch := Dispatch{Token: ID(), TaskARN: "arn:aws:ecs:us-east-2:818416606421:task/utils-bot-csv-trial/" + strings.Repeat("d", 32)}
	if !worker.valid(dispatch) {
		t.Fatal("production client TLS and worker validation disagree")
	}
}

// Supervised retirement of an already attempted synthetic run. This never
// resets the durable recovery lease, starts a task, uploads input or settles.
// Passing this cleanup check does not turn a failed flow into a passing one.
func TestPrivateAWSSupervisedCleanup(t *testing.T) {
	c, cfg := privateAWSInput(t, "cleanup")
	raw, err := os.ReadFile(c.StatePath + ".recovery")
	var checkpoint struct {
		State          privateAWSState
		ProofKey       []byte
		Server, Client csvwire.Bootstrap
		Control        ControllerConfig
	}
	if err != nil || jsonwire.Decode(raw, &checkpoint, 32<<10) != nil || checkpoint.State.Config != c || checkpoint.Control.RunID != c.RunID || checkpoint.Control.JobID != c.RunID || len(checkpoint.ProofKey) != ed25519.PrivateKeySize {
		t.Fatal("original recovery checkpoint missing or mismatched")
	}
	var credential struct {
		AccessKeyID, SecretAccessKey, SessionToken string
		Expires                                    time.Time
	}
	if jsonwire.Decode([]byte(os.Getenv("CSV_PRIVATE_VERIFIER_CREDENTIALS")), &credential, 8192) != nil || credential.Expires.Before(time.Now().Add(time.Minute)) {
		t.Fatal("read-only verifier session unavailable")
	}
	v := VerifierProcess{Executable: os.Getenv("CSV_PRIVATE_VERIFIER_PATH"), BinarySHA: os.Getenv("CSV_PRIVATE_VERIFIER_SHA"), RunID: c.RunID, JobID: c.RunID, Key: checkpoint.ProofKey, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey, SessionToken: credential.SessionToken, CanExpire: true, Expires: credential.Expires}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	controller, err := AssembleController(ctx, checkpoint.Control, cfg, v)
	if err != nil {
		t.Fatal("original controller binding", err)
	}
	job, err := controller.Repo.Get(ctx, c.RunID)
	if err != nil || job == nil || job.Settlement != nil || (job.Financial != "UNPAID" && job.Financial != "AWAITING_PAYMENT") || job.Artifact != "DELETING" {
		t.Fatal("cleanup-only state gate")
	}
	if controller.Fence.StopWriters(ctx, *job) != nil {
		t.Fatal("original task and network absence unconfirmed")
	}
	cleanup := Cleanup{Repo: controller.Repo, Writers: controller.Fence, Objects: controller.Fence, Gate: Gate{Enabled: true}}
	if err := cleanup.Complete(ctx, c.RunID); err != nil {
		t.Fatal("supervised erasure unconfirmed", err)
	}
	job, err = controller.Repo.Get(ctx, c.RunID)
	cap, capErr := controller.Repo.get(ctx, "CAPACITY")
	if err != nil || capErr != nil || job == nil || job.Artifact != "ERASED" || job.Financial != "UNPAID" || avs(cap["used"]) != "0" {
		t.Fatal("final retirement state differs")
	}
	t.Log("PRIVATE_SUPERVISED_CLEANUP_VERIFIED original_tasks_and_enis_absent=true bucket_absent=true erased=true capacity=0 no_dispatch=true no_payment=true flow_passed=false")
}
