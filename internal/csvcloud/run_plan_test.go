package csvcloud

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"strings"
	"testing"
	"time"
)

func TestRunPlanRejectsOverspendLifetimeAndReuse(t *testing.T) {
	w := privateReview()
	p := RunPlan{Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, RunID: w.RunID, JobID: ID(), Account: w.Account, WorkerImage: w.Image, BrokerImage: w.Image, Created: fixtureTime.Unix(), Until: fixtureTime.Add(10 * time.Minute).Unix(), ResourcesUntil: fixtureTime.Add(2 * time.Hour).Unix(), ReservedMicroUSD: 10_000_000, SyntheticOnly: true}
	r, _ := memoryRepo()
	if p.Reserve(ctx, r, fixtureTime) != nil || p.Reserve(ctx, r, fixtureTime) == nil {
		t.Fatal("reused run")
	}
	for _, mode := range []string{"budget", "wall", "resources", "production", "expired", "subnet", "security_group"} {
		bad := p
		now := fixtureTime
		switch mode {
		case "subnet":
			bad.Subnet = "subnet-live"
		case "security_group":
			bad.SecurityGroup = "sg-live"
		case "budget":
			bad.ReservedMicroUSD++
		case "wall":
			bad.Until++
		case "resources":
			bad.ResourcesUntil++
		case "production":
			bad.SyntheticOnly = false
		case "expired":
			now = fixtureTime.Add(11 * time.Minute)
		}
		if bad.valid(now.Unix()) {
			t.Fatal("unsafe run", mode)
		}
	}
}
func TestBrokerProfileRejectsCredentialAndExposureDrift(t *testing.T) {
	w := privateReview()
	b := BrokerReview{Worker: w, Image: w.Image}
	original, e := b.Definition()
	if e != nil || b.Validate(&original) != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*et.TaskDefinition){"role": func(d *et.TaskDefinition) { d.TaskRoleArn = aws.String("prod") }, "secret": func(d *et.TaskDefinition) { d.ContainerDefinitions[0].Secrets[0].ValueFrom = aws.String("foreign") }, "command": func(d *et.TaskDefinition) { d.ContainerDefinitions[0].Command = []string{"unsafe"} }, "port": func(d *et.TaskDefinition) {
		d.ContainerDefinitions[0].PortMappings = []et.PortMapping{{ContainerPort: aws.Int32(80)}}
	}, "mount": func(d *et.TaskDefinition) { d.Volumes = []et.Volume{{Name: aws.String("foreign")}} }} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var d et.TaskDefinition
			_ = json.Unmarshal(raw, &d)
			mutate(&d)
			if b.Validate(&d) == nil {
				t.Fatal("unsafe broker")
			}
		})
	}
}
func TestBrokerConfigRejectsLargeProductionAndForeignMetadata(t *testing.T) {
	w := privateReview()
	b := BrokerBootstrap{RunID: w.RunID, JobID: ID(), Account: w.Account, Table: "utils-bot-csv-private-" + w.RunID[:16], Bucket: "utils-csv-" + w.Account + "-" + w.RunID[:24], Cluster: "arn:aws:ecs:us-east-2:" + w.Account + ":cluster/utils-bot-csv-trial", Definition: "private:1", Subnet: "subnet-0d1659853364bcb35", Prefix: "10.88.0.0/24", Review: w, Until: fixtureTime.Add(10 * time.Minute).Unix()}
	raw, _ := json.Marshal(b)
	if _, e := DecodeBroker(raw, fixtureTime); e == nil {
		t.Fatal("missing wire/credentials accepted")
	}
	if _, e := DecodeBroker([]byte(strings.Repeat("x", 8193)), time.Now()); e == nil {
		t.Fatal("unbounded bootstrap")
	}
}

type brokerECS struct{ fakeECS }

func (f *brokerECS) RunTask(c context.Context, q *ecs.RunTaskInput, opts ...func(*ecs.Options)) (*ecs.RunTaskOutput, error) {
	_, e := f.fakeECS.RunTask(c, q, opts...)
	f.task.ClusterArn = q.Cluster
	f.task.TaskArn = aws.String("arn:aws:ecs:us-east-2:123456789012:task/utils-bot-csv-trial/" + strings.Repeat("b", 32))
	if e != nil {
		return nil, e
	}
	return &ecs.RunTaskOutput{Tasks: []et.Task{f.task}}, nil
}
func TestBrokerLostStartReconcilesOriginalParametersAndPersistsOneARN(t *testing.T) {
	for _, scenario := range []string{"recover", "parameters", "foreign_arn"} {
		t.Run(scenario, func(t *testing.T) {
			proc, j, _, _, _ := processorFixture(t)
			r := proc.Repo
			w := privateReview()
			plan := RunPlan{Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, RunID: w.RunID, JobID: j.ID, Account: w.Account, WorkerImage: w.Image, BrokerImage: w.Image, Created: fixtureTime.Unix(), Until: fixtureTime.Add(10 * time.Minute).Unix(), ResourcesUntil: fixtureTime.Add(2 * time.Hour).Unix(), ReservedMicroUSD: 10_000_000, SyntheticOnly: true}
			if plan.Reserve(ctx, r, fixtureTime) != nil {
				t.Fatal("reserve")
			}
			scheduler := Reaper{Repo: r, RunID: plan.RunID, JobID: plan.JobID, Now: func() time.Time { return fixtureTime }}
			if scheduler.Schedule(ctx, fixtureTime.Add(2*time.Minute).Unix()) != nil {
				t.Fatal("schedule before dispatch")
			}
			review := BrokerReview{Worker: w, Image: w.Image}
			definition, _ := review.Definition()
			definition.TaskDefinitionArn = aws.String("arn:aws:ecs:us-east-2:123456789012:task-definition/" + *definition.Family + ":1")
			raw, _ := json.Marshal(definition)
			client := &brokerECS{fakeECS: fakeECS{definition: definition, lost: true}}
			if _, e := plan.StartBroker(ctx, r, client, review, *definition.TaskDefinitionArn, Hash(raw), "subnet-0d1659853364bcb35", privateTrialSecurityGroup, fixtureTime); e != ErrUnknown {
				t.Fatal("lost start", e)
			}
			if _, e := plan.StartBroker(ctx, r, client, review, *definition.TaskDefinitionArn, Hash(raw), "subnet-0d1659853364bcb35", privateTrialSecurityGroup, fixtureTime); e == nil || client.runs != 1 {
				t.Fatal("broker redispatched")
			}
			m := r.Client.(*memoryDynamo)
			row := m.rows["BROKER/"+plan.RunID]
			if scenario == "parameters" {
				row["parameters"] = str(ID())
			}
			if scenario == "foreign_arn" {
				row["task_arn"] = str("foreign")
			}
			arn, e := plan.ReconcileBroker(ctx, r, client)
			if scenario != "recover" {
				if e == nil {
					t.Fatal("foreign broker context accepted")
				}
				return
			}
			if e != nil || arn != *client.task.TaskArn || avs(row["task_arn"]) != arn {
				t.Fatal("original ARN not durably recovered", e)
			}
			if _, e = plan.ReconcileBroker(ctx, r, client); e != nil || client.runs != 1 {
				t.Fatal("reconciliation not idempotent")
			}
		})
	}
}
func TestControllerRecoveryRejectsMissingStaleAndUnclaimedLease(t *testing.T) {
	p, j, q, _, w := processorFixture(t)
	w.runFail = true
	_ = p.Process(ctx, j.ID, q)
	now := fixtureTime
	c := Controller{Config: ControllerConfig{JobID: j.ID}, Repo: p.Repo}
	c.Reaper = Reaper{Repo: p.Repo, RunID: ID(), JobID: j.ID, Now: func() time.Time { return now }}
	if c.Reaper.Schedule(ctx, now.Add(2*time.Minute).Unix()) != nil {
		t.Fatal("schedule")
	}
	now = now.Add(3 * time.Minute)
	if c.Recover(ctx, j.ID) != ErrConflict {
		t.Fatal("unclaimed recovery bypassed bounds")
	}
	for _, state := range []string{"PENDING", "NEEDS_OPERATOR", "RECOVERING"} {
		old, _ := c.Reaper.read(ctx)
		next := old
		next.Version++
		next.State = state
		next.LeaseToken = ID()
		next.LeaseUntil = now.Add(90 * time.Second).Unix()
		if c.Reaper.save(ctx, &old, next) != nil {
			t.Fatal("claim fixture")
		}
		wrong := context.WithValue(ctx, recoveryLeaseKey{}, recoveryLease{Version: next.Version, Token: ID()})
		if c.Recover(wrong, j.ID) != ErrConflict {
			t.Fatal("stale/unclaimed lease accepted")
		}
	}
}

type racingBrokerECS struct {
	brokerECS
	hook func()
}

func (f *racingBrokerECS) DescribeTaskDefinition(c context.Context, in *ecs.DescribeTaskDefinitionInput, opts ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	result, e := f.brokerECS.DescribeTaskDefinition(c, in, opts...)
	if f.hook != nil {
		f.hook()
	}
	return result, e
}
func TestBrokerCannotStartWithoutRecoveryOrAfterCleanupReservation(t *testing.T) {
	for _, mode := range []string{"unscheduled", "never_started", "job_changed"} {
		t.Run(mode, func(t *testing.T) {
			proc, j, _, _, _ := processorFixture(t)
			r := proc.Repo
			w := privateReview()
			p := RunPlan{Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, RunID: w.RunID, JobID: j.ID, Account: w.Account, WorkerImage: w.Image, BrokerImage: w.Image, Created: fixtureTime.Unix(), Until: fixtureTime.Add(10 * time.Minute).Unix(), ResourcesUntil: fixtureTime.Add(2 * time.Hour).Unix(), ReservedMicroUSD: 10_000_000, SyntheticOnly: true}
			if p.Reserve(ctx, r, fixtureTime) != nil {
				t.Fatal("reserve")
			}
			if mode != "unscheduled" {
				if (Reaper{Repo: r, RunID: p.RunID, JobID: p.JobID, Now: func() time.Time { return fixtureTime }}).Schedule(ctx, fixtureTime.Add(2*time.Minute).Unix()) != nil {
					t.Fatal("schedule")
				}
			}
			review := BrokerReview{Worker: w, Image: w.Image}
			definition, _ := review.Definition()
			definition.TaskDefinitionArn = aws.String("arn:aws:ecs:us-east-2:123456789012:task-definition/" + *definition.Family + ":1")
			raw, _ := json.Marshal(definition)
			client := &racingBrokerECS{brokerECS: brokerECS{fakeECS: fakeECS{definition: definition}}}
			if mode == "never_started" {
				r.Client.(*memoryDynamo).rows["BROKER/"+p.RunID] = map[string]d.AttributeValue{"pk": str("BROKER/" + p.RunID), "state": str("NEVER_STARTED"), "token": str(p.RunID)}
			}
			if mode == "job_changed" {
				client.hook = func() {
					old := readJob(t, r, j.ID)
					next := copyJob(old)
					next.Version++
					next.Artifact = "DELETING"
					if r.Replace(ctx, old, next) != nil {
						t.Fatal("cleanup race")
					}
				}
			}
			if _, e := p.StartBroker(ctx, r, client, review, *definition.TaskDefinitionArn, Hash(raw), "subnet-0d1659853364bcb35", privateTrialSecurityGroup, fixtureTime); e == nil || client.runs != 0 {
				t.Fatal("late broker launched", mode, e)
			}
		})
	}
}
func TestControllerRejectsDriftedDurableBrokerRequest(t *testing.T) {
	w := privateReview()
	c := ControllerConfig{Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, RunID: w.RunID, JobID: ID(), Account: w.Account, Broker: StoppedObserver{Definition: "private:1"}}
	p := RunPlan{RunID: c.RunID, JobID: c.JobID, Account: c.Account}
	raw, _ := json.Marshal(p.brokerRequest(c.Broker.Definition, "subnet-0d1659853364bcb35", privateTrialSecurityGroup))
	row := map[string]d.AttributeValue{"job": str(c.JobID), "token": str(c.RunID), "definition": str(c.Broker.Definition), "definition_hash": str(ID()), "subnet": str("subnet-0d1659853364bcb35"), "security_group": str(privateTrialSecurityGroup), "parameters": str(Hash(raw))}
	if validateBrokerBinding(row, c) != nil {
		t.Fatal("original rejected")
	}
	for _, field := range []string{"job", "token", "definition", "definition_hash", "subnet", "security_group", "parameters"} {
		old := row[field]
		row[field] = str("foreign")
		if validateBrokerBinding(row, c) == nil {
			t.Fatal("drift accepted", field)
		}
		row[field] = old
	}
}

func TestPrivateRunnerRejectsUnreviewedNetworkBeforeProviderCalls(t *testing.T) {
	w := privateReview()
	r := Runner{Wire: &w, Cluster: "arn:aws:ecs:us-east-2:" + w.Account + ":cluster/utils-bot-csv-trial", Subnet: privateTrialSubnet, SecurityGroup: privateTrialSecurityGroup, Gate: Gate{Enabled: true, Dispatch: true}}
	if !r.privateNetwork() {
		t.Fatal("reviewed network rejected")
	}
	for _, mode := range []string{"subnet", "group", "cluster"} {
		bad := r
		switch mode {
		case "subnet":
			bad.Subnet = "subnet-live"
		case "group":
			bad.SecurityGroup = "sg-live"
		case "cluster":
			bad.Cluster = "live"
		}
		if bad.Start(ctx, Message{}) != ErrInvalid || bad.Reconcile(ctx, ID()) != ErrInvalid {
			t.Fatal("network drift reached provider", mode)
		}
	}
}

func TestControllerRechecksOriginalBrokerDefinitionHash(t *testing.T) {
	review := BrokerReview{Worker: privateReview(), Image: privateReview().Image}
	def, _ := review.Definition()
	def.TaskDefinitionArn = aws.String("private:1")
	raw, _ := json.Marshal(def)
	row := map[string]d.AttributeValue{"definition": str("private:1"), "definition_hash": str(Hash(raw))}
	if validateBrokerDefinition(row, &def) != nil {
		t.Fatal("original rejected")
	}
	def.ContainerDefinitions[0].ReadonlyRootFilesystem = aws.Bool(false)
	if validateBrokerDefinition(row, &def) != ErrConflict {
		t.Fatal("definition drift accepted")
	}
}
