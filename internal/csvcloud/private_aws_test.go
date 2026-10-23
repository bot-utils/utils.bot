package csvcloud

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/jsonwire"
)

// These integration checks require an explicit one-shot synthetic gate. Ordinary
// tests never load credentials, create resources, start tasks or submit payment.
type privateAWSConfig struct {
	Operation                                          string
	LargeTransform                                     bool
	RunID, WorkerImage, BrokerImage, StatePath         string
	ExistingWorkerDefinition, ExistingBrokerDefinition string
	ResourcesUntil                                     int64
}
type privateAWSState struct {
	Config                                                     privateAWSConfig
	WorkerDefinition, BrokerDefinition, WorkerHash, BrokerHash string
}

func privateAWSInput(t *testing.T, stage string) (privateAWSConfig, aws.Config) {
	t.Helper()
	if os.Getenv("CSV_PRIVATE_AWS_STAGE") != stage {
		t.Skip("explicit private AWS stage required")
	}
	var c privateAWSConfig
	if jsonwire.Decode([]byte(os.Getenv("CSV_PRIVATE_AWS_CONFIG")), &c, 4096) != nil || !opaque(c.RunID) || os.Getenv("CSV_PRIVATE_AWS_VALIDATE") != c.RunID || !filepath.IsAbs(c.StatePath) {
		t.Fatal("invalid private gate")
	}
	p := RunPlan{RunID: c.RunID, JobID: c.RunID, Account: "999999999999", Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, WorkerImage: c.WorkerImage, BrokerImage: c.BrokerImage, Created: time.Now().Unix(), ReservedMicroUSD: 10_000_000, SyntheticOnly: true, Stream: c.LargeTransform}
	p.Until = p.Created + 600
	p.ResourcesUntil = c.ResourcesUntil
	if !p.valid(time.Now().Unix()) {
		t.Fatal("unreviewed private plan")
	}
	directory, e := os.Lstat(filepath.Dir(c.StatePath))
	if e != nil || !directory.IsDir() || directory.Mode().Perm()&0077 != 0 {
		t.Fatal("state directory must be private")
	}
	cfg, e := awsenv.Load()
	if e != nil {
		t.Fatal("private credentials unavailable")
	}
	cfg.RetryMaxAttempts = 1
	return c, cfg
}
func privateAWSReview(c privateAWSConfig) WireReview {
	return WireReview{Account: "999999999999", RunID: c.RunID, Image: c.WorkerImage, ExecutionRole: "arn:aws:iam::999999999999:role/utils-bot-csv-private-" + c.RunID[:16] + "-worker-execution", SecretARN: "arn:aws:ssm:us-east-2:999999999999:parameter/utils-bot/csv-private/" + c.RunID + "/tls", SyntheticOnly: true, Stream: c.LargeTransform}
}
func requirePrivateAWSCluster(t *testing.T, ctx context.Context, client *ecs.Client) {
	t.Helper()
	arn := "arn:aws:ecs:us-east-2:999999999999:cluster/utils-bot-csv-trial"
	out, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{Clusters: []string{arn}}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if err != nil || !privateClusterReady(out, arn) {
		t.Fatal("isolated cluster must already be active and empty; no registration, upload or task start")
	}
}

func TestPrivateAWSRegister(t *testing.T) {
	c, cfg := privateAWSInput(t, "register")
	if _, e := os.Lstat(c.StatePath); !os.IsNotExist(e) {
		t.Fatal("one-shot state already exists")
	}
	client := ecs.NewFromConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	requirePrivateAWSCluster(t, ctx, client)
	worker := privateAWSReview(c)
	broker := BrokerReview{Worker: worker, Image: c.BrokerImage}
	w, e := worker.Registration()
	if e != nil {
		t.Fatal(e)
	}
	b, e := broker.Registration()
	if e != nil {
		t.Fatal(e)
	}
	state := privateAWSState{Config: c}
	for _, mode := range []string{"worker", "broker"} {
		request := w
		if mode == "broker" {
			request = b
		}
		arn := c.ExistingWorkerDefinition
		if mode == "broker" {
			arn = c.ExistingBrokerDefinition
		}
		if arn == "" {
			result, e := client.RegisterTaskDefinition(ctx, request, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
			if e != nil || result == nil || result.TaskDefinition == nil {
				t.Fatal("private registration failed", e)
			}
			arn = aws.ToString(result.TaskDefinition.TaskDefinitionArn)
		}
		read, e := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(arn)}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
		if e != nil || read == nil || read.TaskDefinition == nil {
			t.Fatal("private definition readback failed")
		}
		raw, _ := json.Marshal(read.TaskDefinition)
		if mode == "worker" {
			e = worker.Validate(read.TaskDefinition)
			state.WorkerDefinition = arn
			state.WorkerHash = Hash(raw)
		} else {
			e = broker.Validate(read.TaskDefinition)
			state.BrokerDefinition = arn
			state.BrokerHash = Hash(raw)
		}
		if e != nil {
			t.Logf("PRIVATE_DEFINITION_READBACK %s", raw)
			t.Fatal("provider definition differs from reviewed profile", mode)
		}
	}
	raw, _ := json.Marshal(state)
	f, e := os.OpenFile(c.StatePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal("private state claim failed")
	}
	defer f.Close()
	if _, e = f.Write(raw); e != nil || f.Sync() != nil {
		t.Fatal("private state write failed")
	}
	t.Logf("PRIVATE_DEFINITIONS_VERIFIED worker=%s broker=%s", state.WorkerDefinition, state.BrokerDefinition)
}
