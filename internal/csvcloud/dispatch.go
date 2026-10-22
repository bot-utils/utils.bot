package csvcloud

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"pdfservice/internal/jsonwire"
)

type SQSAPI interface {
	SendMessage(context.Context, *sqs.SendMessageInput, ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}
type Queue struct {
	Client SQSAPI
	URL    string
	Repo   Repository
	Gate   Gate
}
type Message struct {
	JobID string `json:"job_id"`
	Token string `json:"token"`
}

func DecodeMessage(raw []byte) (Message, error) {
	var m Message
	if jsonwire.Decode(raw, &m, 1024) != nil || !opaque(m.JobID) || !opaque(m.Token) {
		return m, ErrInvalid
	}
	return m, nil
}

// Publish claims the existing transactional outbox once. A lost send reply is
// retained as SEND_UNKNOWN and never automatically redriven.
func (q Queue) Publish(ctx context.Context, id string) error {
	if !q.Gate.Enabled {
		return ErrDisabled
	}
	j, err := q.Repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if j == nil || j.Dispatch == nil || j.Artifact != "QUEUED" {
		return ErrConflict
	}
	row, err := q.Repo.get(ctx, "OUTBOX/"+id)
	if err != nil {
		return err
	}
	state, ok := row["state"].(*d.AttributeValueMemberS)
	if !ok || state.Value != "PENDING" {
		return ErrConflict
	}
	update := func(from, to string) error {
		return q.Repo.txn(ctx, []d.TransactWriteItem{{Update: &d.Update{TableName: aws.String(q.Repo.Table), Key: key("OUTBOX/" + id), UpdateExpression: aws.String("SET #s = :next"), ConditionExpression: aws.String("#s = :old AND #t = :token"), ExpressionAttributeNames: map[string]string{"#s": "state", "#t": "token"}, ExpressionAttributeValues: map[string]d.AttributeValue{":next": str(to), ":old": str(from), ":token": str(j.Dispatch.Token)}}}})
	}
	if err = update("PENDING", "SENDING"); err != nil {
		return err
	}
	body, _ := json.Marshal(Message{j.ID, j.Dispatch.Token})
	_, sendErr := q.Client.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: aws.String(q.URL), MessageBody: aws.String(string(body))}, func(o *sqs.Options) { o.RetryMaxAttempts = 1 })
	stateValue := "SENT"
	if sendErr != nil {
		stateValue = "SEND_UNKNOWN"
	}
	if err = update("SENDING", stateValue); err != nil {
		return ErrUnknown
	}
	if sendErr != nil {
		return ErrUnknown
	}
	return nil
}

type ECSAPI interface {
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
	RunTask(context.Context, *ecs.RunTaskInput, ...func(*ecs.Options)) (*ecs.RunTaskOutput, error)
	ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}
type Runner struct {
	Wire                                                                   *WireReview
	Client                                                                 ECSAPI
	Repo                                                                   Repository
	Gate                                                                   Gate
	Cluster, Definition, Subnet, SecurityGroup, Container, IsolationReview string
	Now                                                                    func() time.Time
}

func (r Runner) now() int64 {
	if r.Now != nil {
		return r.Now().Unix()
	}
	return time.Now().Unix()
}
func (r Runner) request(j Job) *ecs.RunTaskInput {
	request := &ecs.RunTaskInput{Cluster: aws.String(r.Cluster), TaskDefinition: aws.String(r.Definition), ClientToken: aws.String(j.Dispatch.Token), StartedBy: aws.String(j.Dispatch.Token[:32]), Group: aws.String("csv-" + j.Dispatch.Token), Count: aws.Int32(1), LaunchType: et.LaunchTypeFargate, PlatformVersion: aws.String("1.4.0"), NetworkConfiguration: &et.NetworkConfiguration{AwsvpcConfiguration: &et.AwsVpcConfiguration{Subnets: []string{r.Subnet}, SecurityGroups: []string{r.SecurityGroup}, AssignPublicIp: et.AssignPublicIpDisabled}}, Overrides: &et.TaskOverride{ContainerOverrides: []et.ContainerOverride{{Name: aws.String(r.Container), Command: []string{"--job", j.ID, "--dispatch", j.Dispatch.Token}}}}}
	if r.Wire != nil {
		request.Overrides = nil
		request.Tags = []et.Tag{{Key: aws.String("CSVPrivateRun"), Value: aws.String(r.Wire.RunID)}, {Key: aws.String("CSVPrivateKind"), Value: aws.String("worker")}}
	}
	return request
}

// Start only consumes a durable cost reservation. There is one automatic RunTask
// call, no SDK retry and no replacement token after any uncertain outcome.
func (r Runner) Start(ctx context.Context, m Message) error {
	if !r.Gate.Enabled || !r.Gate.Dispatch {
		return ErrDisabled
	}
	if r.Wire != nil && !r.privateNetwork() {
		return ErrInvalid
	}
	if !opaque(r.IsolationReview) || !strings.Contains(r.Definition, ":task-definition/") || !strings.Contains(r.Definition, ":") || r.Container == "" || r.Subnet == "" || r.SecurityGroup == "" {
		return ErrInvalid
	}
	j, err := r.Repo.Get(ctx, m.JobID)
	if err != nil {
		return err
	}
	if j == nil || j.Dispatch == nil || j.Dispatch.Token != m.Token {
		return ErrConflict
	}
	if j.Artifact != "QUEUED" || j.Dispatch.State != "RESERVED" {
		return nil
	}
	if err = r.inspectDefinition(ctx); err != nil {
		return err
	}
	request := r.request(*j)
	raw, _ := json.Marshal(request)
	next := *j
	dispatch := *j.Dispatch
	next.Dispatch = &dispatch
	next.Version++
	next.Artifact = "DISPATCH_RESERVED"
	dispatch.State = "STARTING"
	dispatch.Started = r.now()
	dispatch.Parameters = Hash(raw)
	if err = r.Repo.advanceVerified(ctx, *j, next); err != nil {
		return err
	}
	out, err := r.Client.RunTask(ctx, request, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if err != nil || out == nil || len(out.Failures) != 0 || len(out.Tasks) != 1 {
		return ErrUnknown
	}
	task := out.Tasks[0]
	if aws.ToString(task.Group) != "csv-"+m.Token || aws.ToString(task.StartedBy) != m.Token[:32] || aws.ToString(task.TaskDefinitionArn) != r.Definition || task.TaskArn == nil {
		return ErrUnknown
	}
	finished := next
	dispatchCopy := *next.Dispatch
	finished.Dispatch = &dispatchCopy
	finished.Version++
	finished.Artifact = "RUNNING"
	finished.Dispatch.State = "ACTIVE"
	finished.Dispatch.TaskARN = *task.TaskArn
	return r.Repo.advanceVerified(ctx, next, finished)
}

// Reconcile is read-only at ECS. No RunTask is called, even beyond ECS's token
// idempotency horizon. Zero/multiple matches remain unknown/operator-reviewed.
func (r Runner) Reconcile(ctx context.Context, id string) error {
	if r.Wire != nil && !r.privateNetwork() {
		return ErrInvalid
	}
	if !r.Gate.Enabled {
		return ErrDisabled
	}
	j, err := r.Repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if j == nil || j.Dispatch == nil || j.Dispatch.State != "STARTING" {
		return ErrConflict
	}
	if r.now() < j.Dispatch.Started || r.now()-j.Dispatch.Started >= 24*3600 {
		return ErrUnknown
	}
	raw, _ := json.Marshal(r.request(*j))
	if Hash(raw) != j.Dispatch.Parameters {
		return ErrConflict
	}
	found := map[string]et.Task{}
	for _, status := range []et.DesiredStatus{et.DesiredStatusRunning, et.DesiredStatusStopped} {
		page, err := r.Client.ListTasks(ctx, &ecs.ListTasksInput{Cluster: aws.String(r.Cluster), DesiredStatus: status, MaxResults: aws.Int32(100)}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
		if err != nil || page.NextToken != nil {
			return ErrUnknown
		}
		if len(page.TaskArns) == 0 {
			continue
		}
		observed, err := r.Client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(r.Cluster), Tasks: page.TaskArns}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
		if err != nil || len(observed.Failures) != 0 {
			return ErrUnknown
		}
		for _, t := range observed.Tasks {
			if aws.ToString(t.Group) == "csv-"+j.Dispatch.Token && aws.ToString(t.StartedBy) == j.Dispatch.Token[:32] && aws.ToString(t.TaskDefinitionArn) == r.Definition && t.TaskArn != nil {
				found[*t.TaskArn] = t
			}
		}
	}
	if len(found) != 1 {
		return ErrUnknown
	}
	next := *j
	dispatch := *j.Dispatch
	next.Dispatch = &dispatch
	next.Version++
	for arn, t := range found {
		next.Dispatch.TaskARN = arn
		next.Dispatch.State = "ACTIVE"
		next.Artifact = "RUNNING"
		if aws.ToString(t.LastStatus) == "STOPPED" {
			next.Dispatch.State = "STOPPED_UNVERIFIED"
			next.Artifact = "PROCESSING_UNKNOWN"
		}
	}
	return r.Repo.advanceVerified(ctx, *j, next)
}

// inspectDefinition pins the full reviewed revision, then checks the parser's
// baseline sandbox. Network/transfer isolation still requires AWS preflight.
func (r Runner) inspectDefinition(ctx context.Context) error {
	out, e := r.Client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(r.Definition)}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if e != nil || out.TaskDefinition == nil {
		return ErrUnknown
	}
	d := out.TaskDefinition
	raw, _ := json.Marshal(d)
	if r.Wire != nil {
		if r.Container != "transport" || Hash(raw) != r.IsolationReview || aws.ToString(d.TaskDefinitionArn) != r.Definition {
			return ErrInvalid
		}
		return r.Wire.Validate(d)
	}
	if Hash(raw) != r.IsolationReview || aws.ToString(d.TaskDefinitionArn) != r.Definition || aws.ToString(d.TaskRoleArn) != "" || aws.ToString(d.Cpu) != "1024" || aws.ToString(d.Memory) != "2048" || d.NetworkMode != et.NetworkModeAwsvpc || d.RuntimePlatform == nil || d.RuntimePlatform.CpuArchitecture != et.CPUArchitectureArm64 || d.RuntimePlatform.OperatingSystemFamily != et.OSFamilyLinux || len(d.ContainerDefinitions) != 1 || len(d.Volumes) != 0 {
		return ErrInvalid
	}
	c := d.ContainerDefinitions[0]
	if aws.ToString(c.Name) != r.Container || !strings.Contains(aws.ToString(c.Image), "@sha256:") || aws.ToBool(c.Privileged) || !aws.ToBool(c.ReadonlyRootFilesystem) || aws.ToString(c.User) != "65532:65532" || len(c.Secrets) != 0 || len(c.Environment) != 0 || len(c.EnvironmentFiles) != 0 || len(c.MountPoints) != 0 || len(c.PortMappings) != 0 || c.LinuxParameters == nil || c.LinuxParameters.Capabilities == nil || len(c.LinuxParameters.Capabilities.Add) != 0 || len(c.LinuxParameters.Capabilities.Drop) != 1 || c.LinuxParameters.Capabilities.Drop[0] != "ALL" || c.LogConfiguration != nil {
		return ErrInvalid
	}
	return nil
}

func (r Runner) privateNetwork() bool {
	return r.Wire != nil && r.Subnet == privateTrialSubnet && r.SecurityGroup == privateTrialSecurityGroup && r.Cluster == "arn:aws:ecs:us-east-2:"+r.Wire.Account+":cluster/utils-bot-csv-trial"
}
