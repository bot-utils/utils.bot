package csvcloud

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"time"
)

// RunPlan is a one-shot synthetic reservation, not a production deployment or an
// AWS-enforced spending cap. Unknown starts consume their one attempt forever.
const privateTrialSubnet = "subnet-00000000000000001"
const privateTrialSecurityGroup = "sg-00000000000000001"

type RunPlan struct {
	Subnet, SecurityGroup                            string
	RunID, JobID, Account, WorkerImage, BrokerImage  string
	Created, Until, ResourcesUntil, ReservedMicroUSD int64
	SyntheticOnly                                    bool
	Stream                                           bool
}

func (p RunPlan) valid(now int64) bool {
	w := WireReview{Account: p.Account, RunID: p.RunID, Image: p.WorkerImage, ExecutionRole: "arn:aws:iam::" + p.Account + ":role/utils-bot-csv-private-" + prefix(p.RunID, 16) + "-worker-execution", SecretARN: "arn:aws:ssm:us-east-2:" + p.Account + ":parameter/utils-bot/csv-private/" + p.RunID + "/tls", SyntheticOnly: p.SyntheticOnly, Stream: p.Stream}
	_, e := (BrokerReview{Worker: w, Image: p.BrokerImage}).Definition()
	return p.Subnet == privateTrialSubnet && p.SecurityGroup == privateTrialSecurityGroup && w.valid() && e == nil && opaque(p.JobID) && p.SyntheticOnly && p.ReservedMicroUSD == 10_000_000 && p.Created > 0 && p.Created <= now && p.Until == p.Created+600 && p.ResourcesUntil >= p.Until && p.ResourcesUntil <= p.Created+7200 && now < p.Until
}
func prefix(s string, n int) string {
	if len(s) < n {
		return ""
	}
	return s[:n]
}
func (p RunPlan) Reserve(ctx context.Context, r Repository, now time.Time) error {
	if !p.valid(now.Unix()) {
		return ErrInvalid
	}
	raw, _ := json.Marshal(p)
	return r.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(r.Table), Item: map[string]d.AttributeValue{"pk": str("RUN/" + p.RunID), "data": &d.AttributeValueMemberB{Value: raw}}, ConditionExpression: aws.String("attribute_not_exists(pk)")}}})
}
func (p RunPlan) check(ctx context.Context, r Repository, now time.Time) error {
	if !p.valid(now.Unix()) {
		return ErrInvalid
	}
	row, e := r.get(ctx, "RUN/"+p.RunID)
	if e != nil {
		return e
	}
	b, ok := row["data"].(*d.AttributeValueMemberB)
	expected, _ := json.Marshal(p)
	if !ok || Hash(b.Value) != Hash(expected) {
		return ErrConflict
	}
	return nil
}

// StartWorker requires the same committed run reservation and budget-bearing job
// as the reviewed Runner. It never manufactures another dispatch token.
func (p RunPlan) StartWorker(ctx context.Context, r Runner, m Message, now time.Time) error {
	if p.check(ctx, r.Repo, now) != nil || r.Wire == nil || r.Wire.RunID != p.RunID || r.Wire.Image != p.WorkerImage || r.Wire.Stream != p.Stream || m.JobID != p.JobID || r.Subnet != p.Subnet || r.SecurityGroup != p.SecurityGroup || r.Cluster != "arn:aws:ecs:us-east-2:"+p.Account+":cluster/utils-bot-csv-trial" {
		return ErrInvalid
	}
	j, e := r.Repo.Get(ctx, m.JobID)
	if e != nil || j == nil || j.Dispatch == nil || j.Dispatch.ReservedMicroUSD != p.ReservedMicroUSD {
		return ErrConflict
	}
	if p.requireRecovery(ctx, r.Repo, now) != nil {
		return ErrConflict
	}
	return r.Start(ctx, m)
}

// StartBroker claims a separate durable one-attempt record before calling ECS.
// Lost responses stay STARTING and require read-only exact-token reconciliation;
// this method never retries or mints a new token.
func (p RunPlan) StartBroker(ctx context.Context, r Repository, client ECSAPI, review BrokerReview, definition, hash, subnet, group string, now time.Time) (string, error) {
	if p.check(ctx, r, now) != nil || client == nil || review.Worker.RunID != p.RunID || review.Worker.Stream != p.Stream || review.Image != p.BrokerImage || subnet != p.Subnet || group != p.SecurityGroup || !opaque(hash) {
		return "", ErrInvalid
	}
	j, e := r.Get(ctx, p.JobID)
	if e != nil || j == nil || j.Dispatch == nil || (j.Artifact != "RUNNING" || j.Financial != "UNPAID") {
		return "", ErrConflict
	}
	if p.requireRecovery(ctx, r, now) != nil {
		return "", ErrConflict
	}
	read, e := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(definition)}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if e != nil || read == nil || read.TaskDefinition == nil {
		return "", ErrUnknown
	}
	raw, _ := json.Marshal(read.TaskDefinition)
	if Hash(raw) != hash || aws.ToString(read.TaskDefinition.TaskDefinitionArn) != definition || review.Validate(read.TaskDefinition) != nil {
		return "", ErrInvalid
	}
	cluster := "arn:aws:ecs:us-east-2:" + p.Account + ":cluster/utils-bot-csv-trial"
	request := p.brokerRequest(definition, subnet, group)
	raw, _ = json.Marshal(request)
	pk := "BROKER/" + p.RunID
	item := map[string]d.AttributeValue{"pk": str(pk), "state": str("STARTING"), "parameters": str(Hash(raw)), "job": str(p.JobID), "token": str(p.RunID), "definition": str(definition), "definition_hash": str(hash), "subnet": str(subnet), "security_group": str(group)}
	if r.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(r.Table), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")}}, {ConditionCheck: &d.ConditionCheck{TableName: aws.String(r.Table), Key: key("JOB/" + p.JobID), ConditionExpression: aws.String("#v = :v"), ExpressionAttributeNames: map[string]string{"#v": "version"}, ExpressionAttributeValues: map[string]d.AttributeValue{":v": num(j.Version)}}}}) != nil {
		return "", ErrConflict
	}
	result, e := client.RunTask(ctx, request, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if e != nil || result == nil || len(result.Failures) != 0 || len(result.Tasks) != 1 {
		return "", ErrUnknown
	}
	t := result.Tasks[0]
	if aws.ToString(t.ClusterArn) != cluster || aws.ToString(t.Group) != "csv-broker-"+p.RunID || aws.ToString(t.StartedBy) != p.RunID[:32] || aws.ToString(t.TaskDefinitionArn) != definition || aws.ToString(t.TaskArn) == "" {
		return "", ErrUnknown
	}
	// The original ARN is appended under the original token/parameter fence.
	e = r.txn(ctx, []d.TransactWriteItem{{Update: &d.Update{TableName: aws.String(r.Table), Key: key(pk), UpdateExpression: aws.String("SET #arn = :arn"), ConditionExpression: aws.String("#token = :token AND #parameters = :parameters AND attribute_not_exists(#arn)"), ExpressionAttributeNames: map[string]string{"#arn": "task_arn", "#token": "token", "#parameters": "parameters"}, ExpressionAttributeValues: map[string]d.AttributeValue{":arn": str(*t.TaskArn), ":token": str(p.RunID), ":parameters": item["parameters"]}}}})
	if e != nil {
		return "", ErrUnknown
	}
	return *t.TaskArn, nil
}

// ReconcileBroker is read-only at ECS and never starts a replacement. Multiple,
// missing or paginated matches remain unknown, even after the idempotency window.
func (p RunPlan) ReconcileBroker(ctx context.Context, r Repository, client ECSAPI) (string, error) {
	row, e := r.get(ctx, "BROKER/"+p.RunID)
	if e != nil {
		return "", e
	}
	get := func(k string) string {
		v, ok := row[k].(*d.AttributeValueMemberS)
		if !ok {
			return ""
		}
		return v.Value
	}
	definition, subnet, group := get("definition"), get("subnet"), get("security_group")
	if get("token") != p.RunID || get("job") != p.JobID || definition == "" || subnet != privateTrialSubnet || group != privateTrialSecurityGroup {
		return "", ErrConflict
	}
	request := p.brokerRequest(definition, subnet, group)
	raw, _ := json.Marshal(request)
	if get("parameters") != Hash(raw) {
		return "", ErrConflict
	}
	read, e := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(definition)}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if e != nil || read == nil || read.TaskDefinition == nil {
		return "", ErrUnknown
	}
	raw, _ = json.Marshal(read.TaskDefinition)
	if Hash(raw) != get("definition_hash") {
		return "", ErrConflict
	}
	found := map[string]bool{}
	cluster := aws.ToString(request.Cluster)
	for _, status := range []et.DesiredStatus{et.DesiredStatusRunning, et.DesiredStatusStopped} {
		page, e := client.ListTasks(ctx, &ecs.ListTasksInput{Cluster: aws.String(cluster), DesiredStatus: status, MaxResults: aws.Int32(100)}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
		if e != nil || page == nil || page.NextToken != nil {
			return "", ErrUnknown
		}
		if len(page.TaskArns) == 0 {
			continue
		}
		tasks, e := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: page.TaskArns}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
		if e != nil || tasks == nil || len(tasks.Failures) != 0 {
			return "", ErrUnknown
		}
		for _, t := range tasks.Tasks {
			if aws.ToString(t.ClusterArn) == cluster && aws.ToString(t.TaskDefinitionArn) == definition && aws.ToString(t.Group) == aws.ToString(request.Group) && aws.ToString(t.StartedBy) == aws.ToString(request.StartedBy) && aws.ToString(t.TaskArn) != "" {
				found[*t.TaskArn] = true
			}
		}
	}
	if len(found) != 1 {
		return "", ErrUnknown
	}
	for arn := range found {
		if existing := get("task_arn"); existing != "" {
			if existing != arn {
				return "", ErrConflict
			}
			return arn, nil
		}
		e = r.txn(ctx, []d.TransactWriteItem{{Update: &d.Update{TableName: aws.String(r.Table), Key: key("BROKER/" + p.RunID), UpdateExpression: aws.String("SET #arn = :arn"), ConditionExpression: aws.String("#token = :token AND #parameters = :parameters AND attribute_not_exists(#arn)"), ExpressionAttributeNames: map[string]string{"#arn": "task_arn", "#token": "token", "#parameters": "parameters"}, ExpressionAttributeValues: map[string]d.AttributeValue{":arn": str(arn), ":token": str(p.RunID), ":parameters": str(get("parameters"))}}}})
		if e != nil {
			return "", ErrUnknown
		}
		return arn, nil
	}
	return "", ErrUnknown
}
func (p RunPlan) brokerRequest(definition, subnet, group string) *ecs.RunTaskInput {
	return &ecs.RunTaskInput{Tags: []et.Tag{{Key: aws.String("CSVPrivateRun"), Value: aws.String(p.RunID)}, {Key: aws.String("CSVPrivateKind"), Value: aws.String("broker")}}, Cluster: aws.String("arn:aws:ecs:us-east-2:" + p.Account + ":cluster/utils-bot-csv-trial"), TaskDefinition: aws.String(definition), ClientToken: aws.String(p.RunID), StartedBy: aws.String(p.RunID[:32]), Group: aws.String("csv-broker-" + p.RunID), Count: aws.Int32(1), LaunchType: et.LaunchTypeFargate, PlatformVersion: aws.String("1.4.0"), NetworkConfiguration: &et.NetworkConfiguration{AwsvpcConfiguration: &et.AwsVpcConfiguration{Subnets: []string{subnet}, SecurityGroups: []string{group}, AssignPublicIp: et.AssignPublicIpDisabled}}}
}

func (p RunPlan) requireRecovery(ctx context.Context, r Repository, now time.Time) error {
	scheduled, e := (Reaper{Repo: r, RunID: p.RunID, JobID: p.JobID}).read(ctx)
	if e != nil || scheduled.State != "PENDING" || scheduled.NotBefore <= now.Unix() {
		return ErrConflict
	}
	return nil
}
