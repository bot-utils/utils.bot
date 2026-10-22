package csvcloud

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

var ctx = context.Background()
var fixtureTime = time.Unix(1800000000, 0)

func fixtureJob() Job {
	j := Job{ID: ID(), IntentBinding: ID(), Owner: "0x1111111111111111111111111111111111111111", AdmissionNonceHash: ID(), IdempotencyHash: ID(), RecoveryVerifier: ID(), CapabilityVerifier: ID(), Version: 1, Artifact: "UPLOAD_INCOMPLETE", Financial: "UNPAID", UploadUntil: fixtureTime.Unix() + 300}
	j.Inputs = []Object{{JobID: j.ID, ID: ID(), Slot: "file", Bytes: 8, SHA256: ID()}}
	return j
}

// This fake supplies atomic provider transactions and lost replies; production
// adapter logic, request expressions and CAS versions are exercised unchanged.
type memoryDynamo struct {
	mu           sync.Mutex
	rows         map[string]map[string]d.AttributeValue
	transactions []*dynamodb.TransactWriteItemsInput
	lost         bool
}

func memoryRepo() (Repository, *memoryDynamo) {
	m := &memoryDynamo{rows: map[string]map[string]d.AttributeValue{}}
	return Repository{Client: m, Table: "synthetic", Gate: Gate{Enabled: true}}, m
}
func (m *memoryDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !aws.ToBool(in.ConsistentRead) {
		panic("eventual read")
	}
	return &dynamodb.GetItemOutput{Item: m.rows[in.Key["pk"].(*d.AttributeValueMemberS).Value]}, nil
}
func avs(v d.AttributeValue) string {
	switch x := v.(type) {
	case *d.AttributeValueMemberS:
		return x.Value
	case *d.AttributeValueMemberN:
		return x.Value
	}
	return ""
}
func (m *memoryDynamo) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, opts ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := dynamodb.Options{}
	for _, f := range opts {
		f(&o)
	}
	if o.RetryMaxAttempts != 1 {
		panic("retry enabled")
	}
	m.transactions = append(m.transactions, in)
	for _, v := range in.TransactItems {
		if v.Put != nil {
			p := v.Put
			old := m.rows[avs(p.Item["pk"])]
			if aws.ToString(p.ConditionExpression) == "attribute_not_exists(pk)" && old != nil || aws.ToString(p.ConditionExpression) == "#v = :v" && avs(old["version"]) != avs(p.ExpressionAttributeValues[":v"]) {
				return nil, &d.TransactionCanceledException{}
			}
		} else if v.Update != nil {
			u := v.Update
			old := m.rows[avs(u.Key["pk"])]
			field := "used"
			if u.ExpressionAttributeNames["#reserved"] != "" {
				field = "reserved"
			}
			val, _ := strconv.ParseInt(avs(old[field]), 10, 64)
			if limit := u.ExpressionAttributeValues[":max"]; limit != nil {
				n, _ := strconv.ParseInt(avs(limit), 10, 64)
				if val >= n {
					return nil, &d.TransactionCanceledException{}
				}
			}
			if limit := u.ExpressionAttributeValues[":remaining"]; limit != nil {
				n, _ := strconv.ParseInt(avs(limit), 10, 64)
				if val > n {
					return nil, &d.TransactionCanceledException{}
				}
			}
			if strings.Contains(aws.ToString(u.UpdateExpression), " - :one") && val < 1 {
				return nil, &d.TransactionCanceledException{}
			}
			if expected := u.ExpressionAttributeValues[":job"]; expected != nil && avs(old["job"]) != avs(expected) {
				return nil, &d.TransactionCanceledException{}
			}
			if strings.Contains(aws.ToString(u.ConditionExpression), "#s = :old") && (avs(old["state"]) != avs(u.ExpressionAttributeValues[":old"]) || avs(old["token"]) != avs(u.ExpressionAttributeValues[":token"])) {
				return nil, &d.TransactionCanceledException{}
			}
		}
	}
	for _, v := range in.TransactItems {
		if v.Put != nil {
			m.rows[avs(v.Put.Item["pk"])] = v.Put.Item
		} else if v.Update != nil {
			u := v.Update
			k := avs(u.Key["pk"])
			if m.rows[k] == nil {
				m.rows[k] = map[string]d.AttributeValue{"pk": str(k)}
			}
			if aws.ToString(u.UpdateExpression) == "REMOVE #binding" {
				delete(m.rows[k], "binding")
			}
			if n := u.ExpressionAttributeValues[":next"]; n != nil {
				m.rows[k]["state"] = n
			}
			if strings.Contains(aws.ToString(u.UpdateExpression), "#used") {
				v, _ := strconv.ParseInt(avs(m.rows[k]["used"]), 10, 64)
				if strings.Contains(aws.ToString(u.UpdateExpression), " - :one") {
					v--
				} else {
					v++
				}
				m.rows[k]["used"] = num(v)
			}
			if cost := u.ExpressionAttributeValues[":cost"]; cost != nil {
				v, _ := strconv.ParseInt(avs(m.rows[k]["reserved"]), 10, 64)
				n, _ := strconv.ParseInt(avs(cost), 10, 64)
				m.rows[k]["reserved"] = num(v + n)
			}

		}
	}
	if m.lost {
		m.lost = false
		return nil, errors.New("lost reply")
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}
func seed(t *testing.T, r Repository, j Job) {
	t.Helper()
	if e := r.Create(ctx, j, 2); e != nil {
		t.Fatal(e)
	}
}
func readJob(t *testing.T, r Repository, id string) Job {
	t.Helper()
	j, e := r.Get(ctx, id)
	if e != nil || j == nil {
		t.Fatalf("get: %v", e)
	}
	return *j
}
func TestDynamoAtomicIdentitiesCASAndLostReply(t *testing.T) {
	r, m := memoryRepo()
	j := fixtureJob()
	m.lost = true
	seed(t, r, j)
	if len(m.rows) != 4 {
		t.Fatal("identity/capacity not atomic")
	}
	next := j
	next.Version++
	next.Artifact = "UPLOAD_VERIFIED"
	next.Inputs = append([]Object(nil), j.Inputs...)
	next.Inputs[0].ETag = `"verified"`
	if e := r.Replace(ctx, j, next); e != nil {
		t.Fatal(e)
	}
	if e := r.Replace(ctx, j, next); !errors.Is(e, ErrConflict) {
		t.Fatal("stale CAS", e)
	}
	next.IntentBinding = ID()
	if e := r.Replace(ctx, j, next); !errors.Is(e, ErrInvalid) {
		t.Fatal("mutable identity")
	}
	got := readJob(t, r, j.ID)
	m.rows["JOB/"+j.ID]["version"] = num(got.Version + 1)
	if _, e := r.Get(ctx, j.ID); e != ErrInvalid {
		t.Fatal("inconsistent version accepted")
	}
}
func TestDynamoSerializedConditionsAndDefaultGate(t *testing.T) {
	var captured map[string]any
	cfg := sdkConfig(func(req *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &captured)
		return response(200, `{}`, nil), nil
	})
	c := dynamodb.NewFromConfig(cfg)
	r := Repository{Client: c, Table: "synthetic", Gate: Gate{Enabled: true}}
	j := fixtureJob()
	if e := r.Create(ctx, j, 2); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(captured)
	if !bytes.Contains(raw, []byte("attribute_not_exists")) || bytes.Contains(raw, []byte("ttl")) {
		t.Fatal(string(raw))
	}
	for _, i := range captured["TransactItems"].([]any) {
		if u, ok := i.(map[string]any)["Update"]; ok {
			v := u.(map[string]any)
			if v["ExpressionAttributeNames"].(map[string]any)["#used"] != "used" {
				t.Fatal("counter alias")
			}
		}
	}
	if e := (Repository{}).Create(ctx, j, 1); e != ErrDisabled {
		t.Fatal(e)
	}
}

type transport func(*http.Request) (*http.Response, error)

func (f transport) Do(r *http.Request) (*http.Response, error) { return f(r) }
func sdkConfig(f transport) aws.Config {
	return aws.Config{Region: Region, HTTPClient: f, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "synthetic"}, nil
	}), RetryMaxAttempts: 1}
}
func response(status int, body string, h http.Header) *http.Response {
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}
func storage(cfg aws.Config) Storage {
	c := s3.NewFromConfig(cfg)
	return Storage{Client: c, Presigner: s3.NewPresignClient(c), Bucket: "synthetic-csv", Account: "123456789012", Gate: Gate{Enabled: true}}
}
func manifest(jid string) (Manifest, []byte) {
	plain := []byte("a,b\n1,2\n")
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = z.Write(plain)
	_ = z.Close()
	raw := b.Bytes()
	return Manifest{Object: Object{JobID: jid, ID: ID(), Slot: "result", ETag: `"opaque"`, SHA256: Hash(raw), Bytes: int64(len(raw))}, LogicalBytes: int64(len(plain)), LogicalSHA256: Hash(plain), Rows: 1}, raw
}
func headers(m Manifest) http.Header {
	return http.Header{"Content-Length": {strconv.FormatInt(m.Object.Bytes, 10)}, "Etag": {m.Object.ETag}, "X-Amz-Server-Side-Encryption": {"AES256"}}
}
func TestRealS3PartSignatureAndFullFileHash(t *testing.T) {
	data := []byte("one\ntwo\n")
	u := Upload{Object: Object{JobID: ID(), ID: ID(), Slot: "file", Bytes: int64(len(data)), SHA256: Hash(data)}, ID: "opaque-upload", Parts: []Part{{Number: 1, Bytes: int64(len(data)), SHA256: Hash(data)}}, Expires: time.Now().Add(time.Minute).Unix()}
	calls := 0
	s := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("If-Match") != `"opaque-mpu-2"` && req.Method == "GET" {
			t.Fatal("missing object fence")
		}
		h := http.Header{"Content-Length": {strconv.Itoa(len(data))}, "Etag": {`"opaque-mpu-2"`}, "X-Amz-Server-Side-Encryption": {"AES256"}}
		return response(200, string(data), h), nil
	}))
	grant, e := s.Grant(ctx, u, 1, time.Now())
	if e != nil {
		t.Fatalf("real SDK part signing: %v", e)
	}
	v, _ := url.Parse(grant.URL)
	signed := v.Query().Get("X-Amz-SignedHeaders")
	if !strings.Contains(signed, "content-length") || !strings.Contains(signed, "x-amz-checksum-sha256") || v.Query().Get("x-amz-expected-bucket-owner") != s.Account || http.Header(grant.Headers).Get("Content-Length") != strconv.Itoa(len(data)) {
		t.Fatal("unbound part headers", signed, v.Query(), grant.Headers)
	}
	if calls != 0 {
		t.Fatal("presigning made service call")
	}
	ref, e := s.VerifyInput(ctx, u.Object)
	if e != nil || ref.ETag != `"opaque-mpu-2"` {
		t.Fatal(e)
	}
	u.Object.SHA256 = ID()
	if _, e = s.VerifyInput(ctx, u.Object); e != ErrIntegrity {
		t.Fatal("full-file hash ignored", e)
	}
}
func TestS3ResultIntegrityRangePermitAndDefaultGate(t *testing.T) {
	m, raw := manifest(ID())
	calls := 0
	corrupt := false
	s := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("If-Match") != m.Object.ETag {
			t.Fatal("missing immutable fence")
		}
		h := headers(m)
		body := append([]byte(nil), raw...)
		if corrupt {
			body[len(body)-2] ^= 1
		}
		if req.Header.Get("Range") != "" {
			h.Set("Content-Range", fmt.Sprintf("bytes 0-2/%d", m.Object.Bytes))
			h.Set("Content-Length", "3")
			body = body[:3]
		}
		return response(200, string(body), h), nil
	}))
	if _, e := s.VerifyResult(ctx, m); e != nil {
		t.Fatal(e)
	}
	corrupt = true
	if _, e := s.VerifyResult(ctx, m); e != ErrIntegrity {
		t.Fatal("corrupt gzip accepted", e)
	}
	corrupt = false
	j := fixtureJob()
	j.ID = m.Object.JobID
	j.Result = &m
	j.Financial = "PAID"
	j.Artifact = "RETRIEVABLE"
	j.DownloadClaimed = true
	j.DownloadUntil = fixtureTime.Unix() + 90
	j.ResultUntil = fixtureTime.Unix() + 300
	j.DownloadEnd = 2
	p := &DownloadPermit{job: j}
	body, e := s.ReadPaidRange(ctx, p, fixtureTime.Unix())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(body)
	_ = body.Close()
	if len(b) != 3 {
		t.Fatal("range")
	}
	before := calls
	if _, e = s.ReadPaidRange(ctx, p, fixtureTime.Unix()); e != ErrConflict || calls != before {
		t.Fatal("permit replay")
	}
	if _, e = (Storage{}).VerifyResult(ctx, m); e != ErrDisabled {
		t.Fatal(e)
	}
}

type fakeECS struct {
	runs, describes int
	lost            bool
	definition      et.TaskDefinition
	task            et.Task
}

func (f *fakeECS) DescribeTaskDefinition(_ context.Context, _ *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	f.describes++
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &f.definition}, nil
}
func (f *fakeECS) RunTask(_ context.Context, in *ecs.RunTaskInput, _ ...func(*ecs.Options)) (*ecs.RunTaskOutput, error) {
	f.runs++
	if in.ClientToken == nil || aws.ToInt32(in.Count) != 1 || in.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp != et.AssignPublicIpDisabled {
		panic("unsafe task")
	}
	f.task = et.Task{TaskArn: aws.String("arn:synthetic:owned"), Group: in.Group, StartedBy: in.StartedBy, TaskDefinitionArn: in.TaskDefinition, LastStatus: aws.String("RUNNING")}
	if f.lost {
		return nil, errors.New("lost")
	}
	return &ecs.RunTaskOutput{Tasks: []et.Task{f.task}}, nil
}
func (f *fakeECS) ListTasks(_ context.Context, _ *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{TaskArns: []string{*f.task.TaskArn}}, nil
}
func (f *fakeECS) DescribeTasks(_ context.Context, _ *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{Tasks: []et.Task{f.task}}, nil
}
func taskDefinition() et.TaskDefinition {
	return et.TaskDefinition{TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-2:123456789012:task-definition/csv:1"), Cpu: aws.String("1024"), Memory: aws.String("2048"), NetworkMode: et.NetworkModeAwsvpc, RuntimePlatform: &et.RuntimePlatform{CpuArchitecture: et.CPUArchitectureArm64, OperatingSystemFamily: et.OSFamilyLinux}, ContainerDefinitions: []et.ContainerDefinition{{Name: aws.String("parser"), Image: aws.String("synthetic@sha256:" + strings.Repeat("a", 64)), User: aws.String("65532:65532"), ReadonlyRootFilesystem: aws.Bool(true), LinuxParameters: &et.LinuxParameters{Capabilities: &et.KernelCapabilities{Drop: []string{"ALL"}}}}}}
}
func queued(t *testing.T) (Repository, Job) {
	r, _ := memoryRepo()
	j := fixtureJob()
	seed(t, r, j)
	n := j
	n.Version++
	n.Artifact = "UPLOAD_VERIFIED"
	n.Inputs = append([]Object(nil), j.Inputs...)
	n.Inputs[0].ETag = `"verified"`
	if e := r.Replace(ctx, j, n); e != nil {
		t.Fatal(e)
	}
	j, e := r.Queue(ctx, n, ID(), 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	return r, j
}
func TestDispatchAmbiguityDuplicateAndHorizon(t *testing.T) {
	r, j := queued(t)
	f := &fakeECS{lost: true, definition: taskDefinition()}
	raw, _ := json.Marshal(f.definition)
	runner := Runner{Client: f, Repo: r, Gate: Gate{Enabled: true, Dispatch: true}, Cluster: "synthetic", Definition: *f.definition.TaskDefinitionArn, Subnet: "synthetic", SecurityGroup: "synthetic", Container: "parser", IsolationReview: Hash(raw), Now: func() time.Time { return fixtureTime }}
	m := Message{j.ID, j.Dispatch.Token}
	if e := runner.Start(ctx, m); e != ErrUnknown {
		t.Fatal(e)
	}
	if e := runner.Start(ctx, m); e != nil || f.runs != 1 {
		t.Fatal("duplicate dispatch", e, f.runs)
	}
	runner.Now = func() time.Time { return fixtureTime.Add(25 * time.Hour) }
	if e := runner.Reconcile(ctx, j.ID); e != ErrUnknown || f.runs != 1 {
		t.Fatal("expired idempotency restarted")
	}
	runner.Now = func() time.Time { return fixtureTime }
	if e := runner.Reconcile(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	if readJob(t, r, j.ID).Artifact != "RUNNING" || f.runs != 1 {
		t.Fatal("reconcile")
	}
	f.definition.TaskRoleArn = aws.String("credential-bearing")
	if e := runner.inspectDefinition(ctx); e != ErrInvalid {
		t.Fatal("changed task accepted")
	}
	runner.Gate = Gate{}
	if e := runner.Start(ctx, m); e != ErrDisabled {
		t.Fatal(e)
	}
}

type fakeSQS struct {
	calls int
	lost  bool
}

func (f *fakeSQS) SendMessage(_ context.Context, in *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.calls++
	m, e := DecodeMessage([]byte(aws.ToString(in.MessageBody)))
	if e != nil || !opaque(m.JobID) || len(in.MessageAttributes) != 0 {
		panic("queue metadata")
	}
	if f.lost {
		return nil, errors.New("lost")
	}
	return &sqs.SendMessageOutput{}, nil
}
func TestOutboxUnknownNeverAutomaticallyResends(t *testing.T) {
	r, j := queued(t)
	f := &fakeSQS{lost: true}
	q := Queue{Repo: r, Client: f, URL: "synthetic", Gate: Gate{Enabled: true}}
	if e := q.Publish(ctx, j.ID); e != ErrUnknown {
		t.Fatal(e)
	}
	if e := q.Publish(ctx, j.ID); e != ErrConflict || f.calls != 1 {
		t.Fatal("resend", e, f.calls)
	}
	if _, e := DecodeMessage([]byte(`{"job_id":"x","token":"y","secret":"bad"}`)); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestAWSFactoryRegionAndOverride(t *testing.T) {
	cfg := sdkConfig(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected call"); return nil, nil })
	if _, e := clients(cfg); e != nil {
		t.Fatal(e)
	}
	cfg.Region = "us-east-1"
	if _, e := clients(cfg); e != ErrInvalid {
		t.Fatal(e)
	}
	cfg.Region = Region
	cfg.BaseEndpoint = aws.String("http://localhost")
	if _, e := clients(cfg); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestDownloadReservationCASAndImmutableManifest(t *testing.T) {
	r, j := queued(t)
	m, _ := manifest(j.ID)
	n := copyJob(j)
	n.Version++
	n.Result = &m
	n.Artifact = "RETRIEVABLE"
	n.Financial = "PAID"
	n.Settlement = &Settlement{ID: ID(), Nonce: "0x" + ID(), Payer: n.Owner, Receiver: "0x2222222222222222222222222222222222222222", Asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", Network: "eip155:8453", Amount: "12345", State: "PAID", Transaction: "0x" + ID(), Started: fixtureTime.Unix(), ValidBefore: fixtureTime.Unix() + 180}
	n.ResultUntil = fixtureTime.Unix() + 600
	// Preexisting finalized state is a provider fixture, not a transition that
	// callers may manufacture with generic Replace.
	store := r.Client.(*memoryDynamo)
	store.rows["JOB/"+j.ID] = row(n)
	reserved, e := r.ReserveDownload(ctx, n, ID(), 0, 2, fixtureTime.Unix())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.ReserveDownload(ctx, n, ID(), 0, 2, fixtureTime.Unix()); e != ErrConflict {
		t.Fatal(e)
	}
	permit, e := r.ClaimDownload(ctx, reserved, fixtureTime.Unix())
	if e != nil || permit == nil {
		t.Fatal(e)
	}
	if _, e = r.ClaimDownload(ctx, reserved, fixtureTime.Unix()); e != ErrConflict {
		t.Fatal(e)
	}
	current := readJob(t, r, j.ID)
	mut := copyJob(current)
	mut.Version++
	mut.Result.Rows++
	if e = r.Replace(ctx, current, mut); e != ErrInvalid {
		t.Fatal("mutable published result")
	}
	if e = r.FinishDownload(ctx, current, current.DownloadLease); e != nil {
		t.Fatal(e)
	}

}

func TestS3MultipartCompletionUsesConditionalWriteAndWholeHash(t *testing.T) {
	for _, mode := range []string{"complete", "wrong-part", "lost-completion"} {
		t.Run(mode, func(t *testing.T) {
			data := []byte("a,b\n1,2\n")
			u := Upload{Object: Object{JobID: ID(), ID: ID(), Slot: "file", Bytes: int64(len(data)), SHA256: Hash(data)}, ID: "owned-upload", Parts: []Part{{Number: 1, Bytes: int64(len(data)), SHA256: Hash(data)}}}
			completions := 0
			s := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
				h := http.Header{"Content-Length": {strconv.Itoa(len(data))}, "Etag": {`"mpu-1"`}, "X-Amz-Server-Side-Encryption": {"AES256"}}
				if req.URL.Query().Get("uploadId") != "" {
					if req.Method == "GET" {
						sum := checksum(u.Parts[0].SHA256)
						if mode == "wrong-part" {
							sum = checksum(ID())
						}
						return response(200, fmt.Sprintf(`<ListPartsResult><IsTruncated>false</IsTruncated><Part><PartNumber>1</PartNumber><ETag>opaque</ETag><Size>%d</Size><ChecksumSHA256>%s</ChecksumSHA256></Part></ListPartsResult>`, len(data), sum), nil), nil
					}
					completions++
					if req.Header.Get("If-None-Match") != "*" || req.Header.Get("X-Amz-Mp-Object-Size") != strconv.Itoa(len(data)) {
						t.Fatal("unfenced complete")
					}
					if mode == "lost-completion" {
						return nil, errors.New("lost")
					}
					return response(200, `<CompleteMultipartUploadResult><ETag>"mpu-1"</ETag><ChecksumSHA256>composite-not-file-sha</ChecksumSHA256></CompleteMultipartUploadResult>`, nil), nil
				}
				return response(200, string(data), h), nil
			}))
			_, e := s.Complete(ctx, u)
			switch mode {
			case "complete":
				if e != nil || completions != 1 {
					t.Fatal(e, completions)
				}
			case "wrong-part":
				if e != ErrIntegrity || completions != 0 {
					t.Fatal(e, completions)
				}
			case "lost-completion":
				if e != ErrUnknown || completions != 1 {
					t.Fatal("completion retried", e, completions)
				}
			}
		})
	}
}
func TestLostMPUCreationIsReadOnlyRecovered(t *testing.T) {
	for _, matches := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(matches), func(t *testing.T) {
			u := Upload{Object: Object{JobID: ID(), ID: ID(), Slot: "file", Bytes: 8, SHA256: ID()}, Parts: []Part{{Number: 1, Bytes: 8, SHA256: ID()}}}
			creates := 0
			s := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
				if req.Method == "POST" {
					creates++
					return nil, errors.New("lost")
				}
				body := `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>`
				for range matches {
					body += `<Upload><Key>` + u.Object.key(false) + `</Key><UploadId>owned-upload</UploadId></Upload>`
				}
				body += `</ListMultipartUploadsResult>`
				return response(200, body, nil), nil
			}))
			if _, e := s.Begin(ctx, u); e != ErrUnknown || creates != 1 {
				t.Fatal(e, creates)
			}
			found, e := s.RecoverBegin(ctx, u)
			if matches == 1 {
				if e != nil || found.ID != "owned-upload" {
					t.Fatal(e)
				}
			} else if e != ErrUnknown {
				t.Fatal("ambiguous create recovered", e)
			}
			if creates != 1 {
				t.Fatal("created replacement")
			}
		})
	}
}
func TestActiveS3CleanupChecksAbsenceAndOwnedKeys(t *testing.T) {
	for _, mode := range []string{"clean", "outside-prefix", "still-present"} {
		t.Run(mode, func(t *testing.T) {
			j := fixtureJob()
			lists := map[string]int{}
			deletes := 0
			aborts := 0
			s := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
				q := req.URL.Query()
				prefix := q.Get("prefix")
				if _, ok := q["uploads"]; ok {
					lists["mp"+prefix]++
					body := `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>`
					if lists["mp"+prefix] == 1 {
						body += `<Upload><Key>` + prefix + strings.Repeat("a", 64) + `</Key><UploadId>owned</UploadId></Upload>`
					}
					body += `</ListMultipartUploadsResult>`
					return response(200, body, nil), nil
				}
				if q.Get("list-type") == "2" {
					lists[prefix]++
					body := `<ListBucketResult><IsTruncated>false</IsTruncated>`
					if lists[prefix] == 1 || mode == "still-present" {
						k := prefix + strings.Repeat("a", 64)
						if mode == "outside-prefix" {
							k = "inputs/someone-else/foreign"
						}
						body += `<Contents><Key>` + k + `</Key><ETag>opaque</ETag><Size>8</Size></Contents>`
					}
					body += `</ListBucketResult>`
					return response(200, body, nil), nil
				}
				if req.Method == "DELETE" {
					if q.Get("uploadId") != "" {
						aborts++
					} else {
						deletes++
						if req.Header.Get("If-Match") == "" {
							t.Fatal("unconditional delete")
						}
					}
					return response(204, "", nil), nil
				}
				t.Fatal("unexpected storage operation")
				return nil, nil
			}))
			e := s.EraseAndVerify(ctx, j)
			if mode == "clean" {
				if e != nil || deletes != 2 || aborts != 2 {
					t.Fatal(e, deletes, aborts)
				}
			} else if e != ErrCleanup {
				t.Fatal("cleanup falsely confirmed", e)
			}
		})
	}
}
func TestCapacityFreedExactlyOnceAfterCleanup(t *testing.T) {
	r, m := memoryRepo()
	j := fixtureJob()
	seed(t, r, j)
	other := fixtureJob()
	seed(t, r, other)
	if e := r.Create(ctx, fixtureJob(), 2); e != ErrConflict {
		t.Fatal("unbounded active capacity")
	}
	n := j
	n.Version++
	n.Artifact = "DELETING"
	if e := r.Replace(ctx, j, n); e != nil {
		t.Fatal(e)
	}
	c := Cleanup{Repo: r, Writers: &fenceStub{}, Objects: &eraseStub{}, Gate: Gate{Enabled: true}}
	if e := c.Complete(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	if m.rows["IDEMPOTENCY/"+j.IdempotencyHash]["binding"] != nil || m.rows["NONCE/"+j.AdmissionNonceHash]["binding"] != nil {
		t.Fatal("intent hash retained in tombstones")
	}
	if avs(m.rows["CAPACITY"]["used"]) != "1" {
		t.Fatal("capacity not freed")
	}
	if e := c.Complete(ctx, j.ID); e != nil || avs(m.rows["CAPACITY"]["used"]) != "1" {
		t.Fatal("double decrement")
	}
	seed(t, r, fixtureJob())
}
func TestFixedEventsDistinguishRejectionFromUncertainty(t *testing.T) {
	for _, e := range []Event{InitialQuote, Requote, MalformedPayment, PaymentUnknown, ProviderVerifyFailure, ProviderSettleFailure} {
		if e.PayerRejected() || e.Record().PayerRejected {
			t.Fatal("uncertain/unsigned event counted as payer rejection", e)
		}
	}
	if !PaymentRejected.PayerRejected() {
		t.Fatal("explicit rejection missing")
	}
	if Event(255).Name() != "unknown" {
		t.Fatal("free-form event")
	}
}

func TestS3ResultPutUsesExactChecksumAndConditionalWrite(t *testing.T) {
	m, raw := manifest(ID())
	puts := 0
	s := storage(sdkConfig(func(req *http.Request) (*http.Response, error) {
		h := headers(m)
		h.Set("Etag", `"opaque"`)
		if req.Method == "PUT" {
			puts++
			if req.Header.Get("If-None-Match") != "*" || req.Header.Get("X-Amz-Checksum-Sha256") != checksum(m.Object.SHA256) || req.ContentLength != m.Object.Bytes {
				t.Fatal("unbounded result upload")
			}
			got, e := io.ReadAll(req.Body)
			if e != nil || !bytes.Equal(got, raw) {
				t.Fatal("result body", e)
			}
			return response(200, "", h), nil
		}
		return response(200, string(raw), h), nil
	}))
	m.Object.ETag = ""
	out, e := s.PutResult(ctx, m, bytes.NewReader(raw))
	if e != nil || out.Object.ETag != `"opaque"` || puts != 1 {
		t.Fatal(e, puts)
	}
}

type inputStub struct{ fail bool }

func (i inputStub) VerifyInput(_ context.Context, o Object) (Object, error) {
	if i.fail {
		return o, ErrIntegrity
	}
	o.ETag = `"verified"`
	return o, nil
}
func TestArtifactsRequireVerifiedUploadsAndMatchingWorker(t *testing.T) {
	r, _ := memoryRepo()
	j := fixtureJob()
	j.Inputs = []Object{{JobID: j.ID, ID: ID(), Slot: "file", SHA256: ID(), Bytes: 8}}
	seed(t, r, j)
	a := Artifacts{Repo: r, Inputs: inputStub{fail: true}, Results: &fakeVerifier{}, Gate: Gate{Enabled: true}, Now: func() time.Time { return fixtureTime }}
	if e := a.AcceptUploads(ctx, j.ID); e != ErrIntegrity || readJob(t, r, j.ID).Artifact != "UPLOAD_INCOMPLETE" {
		t.Fatal(e)
	}
	a.Inputs = inputStub{}
	if e := a.AcceptUploads(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	verified := readJob(t, r, j.ID)
	if verified.Inputs[0].ETag == "" || verified.Artifact != "UPLOAD_VERIFIED" {
		t.Fatal("unverified upload")
	}
	queued, e := r.Queue(ctx, verified, ID(), 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	reserved := copyJob(queued)
	reserved.Version++
	reserved.Artifact = "DISPATCH_RESERVED"
	reserved.Dispatch.State = "STARTING"
	reserved.Dispatch.Started = fixtureTime.Unix()
	reserved.Dispatch.Parameters = ID()
	if e = r.Replace(ctx, queued, reserved); e != nil {
		t.Fatal(e)
	}
	running := copyJob(reserved)
	running.Version++
	running.Artifact = "RUNNING"
	running.Dispatch.State = "ACTIVE"
	if e = r.Replace(ctx, reserved, running); e != nil {
		t.Fatal(e)
	}
	m, _ := manifest(j.ID)
	if e = a.PublishResult(ctx, j.ID, ID(), m, fixtureTime.Unix()+1800); e != ErrConflict {
		t.Fatal("stale worker")
	}
	a.Results = &fakeVerifier{fail: true}
	if e = a.PublishResult(ctx, j.ID, running.Dispatch.Token, m, fixtureTime.Unix()+1800); e != ErrIntegrity {
		t.Fatal("bad result published")
	}
	a.Results = &fakeVerifier{}
	if e = a.PublishResult(ctx, j.ID, running.Dispatch.Token, m, fixtureTime.Unix()+1800); e != nil {
		t.Fatal(e)
	}
	if readJob(t, r, j.ID).Financial != "AWAITING_PAYMENT" {
		t.Fatal("result not durable before payment")
	}
}

func TestArtifactLifecycleRejectsSkippedStatesAndChangedInputs(t *testing.T) {
	r, _ := memoryRepo()
	j := fixtureJob()
	seed(t, r, j)
	for _, state := range []string{"QUEUED", "RUNNING", "RESULT_PREPARED", "QUARANTINED", "RETRIEVABLE", "ERASED"} {
		n := copyJob(j)
		n.Version++
		n.Artifact = state
		if e := r.Replace(ctx, j, n); e != ErrInvalid {
			t.Fatal("skipped state accepted", state, e)
		}
	}
	n := copyJob(j)
	n.Version++
	n.Artifact = "UPLOAD_VERIFIED"
	n.Inputs[0].ETag = `"verified"`
	n.Inputs[0].SHA256 = ID()
	if e := r.Replace(ctx, j, n); e != ErrInvalid {
		t.Fatal("changed input during completion")
	}
	n.Inputs[0].SHA256 = j.Inputs[0].SHA256
	if e := r.Replace(ctx, j, n); e != nil {
		t.Fatal("legal upload completion", e)
	}
	mut := copyJob(n)
	mut.Version++
	mut.Inputs[0].SHA256 = ID()
	if e := r.Replace(ctx, n, mut); e != ErrInvalid {
		t.Fatal("changed accepted input")
	}
	q, e := r.Queue(ctx, n, ID(), 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	mut = copyJob(q)
	mut.Version++
	mut.Inputs[0].ID = ID()
	if e = r.Replace(ctx, q, mut); e != ErrInvalid {
		t.Fatal("changed queued input")
	}
	deleting := copyJob(q)
	deleting.Version++
	deleting.Artifact = "DELETING"
	if e = r.Replace(ctx, q, deleting); e != nil {
		t.Fatal("legal queue cleanup", e)
	}
}

func TestArtifactMapRejectsOtherwiseValidSkippedDispatch(t *testing.T) {
	_, q := queued(t)
	n := copyJob(q)
	n.Version++
	n.Artifact = "RUNNING"
	n.Dispatch.State = "ACTIVE"
	n.Dispatch.Started = fixtureTime.Unix()
	n.Dispatch.Parameters = ID()
	n.Dispatch.TaskARN = "arn:synthetic:owned"
	if !n.valid() {
		t.Fatal("fixture must isolate transition rule")
	}
	if validReplacement(q, n) {
		t.Fatal("queued task skipped durable dispatch reservation")
	}
}
