package csvcloud

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type lifecycleStub struct {
	task       et.Task
	definition et.TaskDefinition
	stops      int
	failStop   bool
}

func (s *lifecycleStub) DescribeTasks(_ context.Context, q *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	if len(q.Tasks) != 1 || q.Tasks[0] != aws.ToString(s.task.TaskArn) {
		return nil, ErrInvalid
	}
	return &ecs.DescribeTasksOutput{Tasks: []et.Task{s.task}}, nil
}
func (s *lifecycleStub) DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &s.definition}, nil
}
func (s *lifecycleStub) StopTask(_ context.Context, q *ecs.StopTaskInput, _ ...func(*ecs.Options)) (*ecs.StopTaskOutput, error) {
	s.stops++
	if s.failStop || aws.ToString(q.Task) != aws.ToString(s.task.TaskArn) {
		return nil, ErrUnknown
	}
	s.task.LastStatus = aws.String("STOPPED")
	return &ecs.StopTaskOutput{Task: &s.task}, nil
}

type networkStub struct {
	calls int
	fail  bool
	ids   []string
}

func (s *networkStub) VerifyAbsent(_ context.Context, ids []string) error {
	s.calls++
	s.ids = ids
	if s.fail {
		return ErrCleanup
	}
	return nil
}
func workerFixture() (PrivateWorker, Dispatch, *lifecycleStub, *networkStub) {
	review := privateReview()
	def, _ := review.Definition()
	def.TaskDefinitionArn = aws.String("arn:aws:ecs:us-east-2:123456789012:task-definition/" + aws.ToString(def.Family) + ":1")
	cluster := "arn:aws:ecs:us-east-2:123456789012:cluster/utils-bot-csv-trial"
	dispatch := Dispatch{Token: strings.Repeat("c", 64), TaskARN: "arn:aws:ecs:us-east-2:123456789012:task/utils-bot-csv-trial/" + strings.Repeat("d", 32)}
	s := &lifecycleStub{definition: def, task: et.Task{TaskArn: aws.String(dispatch.TaskARN), ClusterArn: aws.String(cluster), TaskDefinitionArn: def.TaskDefinitionArn, Group: aws.String("csv-" + dispatch.Token), StartedBy: aws.String(dispatch.Token[:32]), PlatformVersion: aws.String("1.4.0"), LaunchType: et.LaunchTypeFargate, LastStatus: aws.String("RUNNING"), Attachments: []et.Attachment{{Type: aws.String("ElasticNetworkInterface"), Details: []et.KeyValuePair{{Name: aws.String("subnetId"), Value: aws.String("subnet-private")}, {Name: aws.String("networkInterfaceId"), Value: aws.String("eni-0123456789abcdef0")}, {Name: aws.String("privateIPv4Address"), Value: aws.String("10.88.0.5")}}}}}}
	n := &networkStub{}
	return PrivateWorker{Review: &review, Client: s, Verifier: n, Cluster: cluster, Definition: aws.ToString(def.TaskDefinitionArn), Subnet: "subnet-private", Prefix: netip.MustParsePrefix("10.88.0.0/24"), TLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool(), ServerName: "csv-worker", Certificates: []tls.Certificate{{}}, NextProtos: []string{"utilsbot-csv/1"}}, Gate: Gate{Enabled: true}}, dispatch, s, n
}
func TestPrivateLifecycleStopsOriginalTaskAndRequiresSeparateNetworkWitness(t *testing.T) {
	w, d, s, n := workerFixture()
	if e := w.StopAndVerify(context.Background(), d); e != nil || s.stops != 1 || n.calls != 1 || len(n.ids) != 1 || n.ids[0] != "eni-0123456789abcdef0" {
		t.Fatal("stop/ENI proof failed", e)
	}
	if e := w.StopAndVerify(context.Background(), d); e != nil || s.stops != 1 {
		t.Fatal("stopped task should not be redispatched or stopped again")
	}
}
func TestPrivateLifecycleRejectsForeignTasksEndpointsOverridesAndUncertainty(t *testing.T) {
	for _, scenario := range []string{"foreign_task", "foreign_token", "foreign_subnet", "foreign_ip", "extra_eni", "override", "stop_unknown", "network_unknown", "no_witness", "disabled", "unsafe_tls"} {
		t.Run(scenario, func(t *testing.T) {
			w, d, s, n := workerFixture()
			switch scenario {
			case "foreign_task":
				d.TaskARN += "x"
			case "foreign_token":
				s.task.StartedBy = aws.String("foreign")
			case "foreign_subnet":
				s.task.Attachments[0].Details[0].Value = aws.String("subnet-live")
			case "foreign_ip":
				s.task.Attachments[0].Details[2].Value = aws.String("169.254.169.254")
			case "extra_eni":
				s.task.Attachments = append(s.task.Attachments, s.task.Attachments[0])
			case "override":
				s.task.Overrides = &et.TaskOverride{TaskRoleArn: aws.String("credentialed")}
			case "stop_unknown":
				s.failStop = true
			case "network_unknown":
				n.fail = true
			case "no_witness":
				w.Verifier = nil
			case "disabled":
				w.Gate.Enabled = false
			case "unsafe_tls":
				w.TLS.InsecureSkipVerify = true
			}
			if w.StopAndVerify(context.Background(), d) == nil {
				t.Fatal("unverified lifecycle accepted")
			}
			if scenario != "stop_unknown" && scenario != "network_unknown" && s.stops != 0 {
				t.Fatal("foreign or drifted task stopped")
			}
		})
	}
}
