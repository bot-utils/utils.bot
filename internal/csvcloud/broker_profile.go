package csvcloud

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"reflect"
	"strings"
)

// BrokerReview is separate from the credential-free worker profile. Secrets
// contains only this run's bootstrap; taskRole provides this job's data access.
type BrokerReview struct {
	Worker WireReview
	Image  string
}

func (b BrokerReview) Definition() (et.TaskDefinition, error) {
	w := b.Worker
	prefix := w.Account + ".dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-private@sha256:"
	if !w.valid() || !strings.HasPrefix(b.Image, prefix) || !opaque(strings.TrimPrefix(b.Image, prefix)) {
		return et.TaskDefinition{}, ErrInvalid
	}
	return et.TaskDefinition{Family: aws.String("utils-bot-csv-private-" + w.RunID[:16] + "-broker"), ExecutionRoleArn: aws.String("arn:aws:iam::" + w.Account + ":role/utils-bot-csv-private-" + w.RunID[:16] + "-broker-execution"), TaskRoleArn: aws.String("arn:aws:iam::" + w.Account + ":role/utils-bot-csv-private-" + w.RunID[:16] + "-broker"), NetworkMode: et.NetworkModeAwsvpc, RequiresCompatibilities: []et.Compatibility{et.CompatibilityFargate}, Cpu: aws.String("1024"), Memory: aws.String("2048"), RuntimePlatform: &et.RuntimePlatform{CpuArchitecture: et.CPUArchitectureArm64, OperatingSystemFamily: et.OSFamilyLinux}, ContainerDefinitions: []et.ContainerDefinition{{Name: aws.String("broker"), Image: aws.String(b.Image), User: aws.String("65532:65532"), Command: []string{"--synthetic-run"}, Essential: aws.Bool(true), Privileged: aws.Bool(false), ReadonlyRootFilesystem: aws.Bool(true), StopTimeout: aws.Int32(30), Secrets: []et.Secret{{Name: aws.String("CSV_BROKER_BOOTSTRAP"), ValueFrom: aws.String("arn:aws:ssm:us-east-2:" + w.Account + ":parameter/utils-bot/csv-private/" + w.RunID + "/broker")}}, Environment: []et.KeyValuePair{{Name: aws.String("AWS_REGION"), Value: aws.String(Region)}}, LinuxParameters: &et.LinuxParameters{Capabilities: &et.KernelCapabilities{Drop: []string{"ALL"}}}, Ulimits: []et.Ulimit{{Name: et.UlimitNameCore, SoftLimit: 0, HardLimit: 0}}}}}, nil
}
func (b BrokerReview) Validate(d *et.TaskDefinition) error {
	expected, e := b.Definition()
	if e != nil || d == nil {
		return ErrInvalid
	}
	actual := *d
	actual.TaskDefinitionArn = nil
	actual.Revision = 0
	actual.Status = ""
	actual.RegisteredAt = nil
	actual.RegisteredBy = nil
	actual.DeregisteredAt = nil
	actual.RequiresAttributes = nil
	actual.Compatibilities = nil
	if !reflect.DeepEqual(actual, expected) {
		return ErrInvalid
	}
	return nil
}

func (b BrokerReview) Registration() (*ecs.RegisterTaskDefinitionInput, error) {
	d, e := b.Definition()
	if e != nil {
		return nil, e
	}
	return &ecs.RegisterTaskDefinitionInput{Family: d.Family, ExecutionRoleArn: d.ExecutionRoleArn, TaskRoleArn: d.TaskRoleArn, NetworkMode: d.NetworkMode, ContainerDefinitions: d.ContainerDefinitions, Cpu: d.Cpu, Memory: d.Memory, RuntimePlatform: d.RuntimePlatform, RequiresCompatibilities: d.RequiresCompatibilities, Tags: []et.Tag{{Key: aws.String("CSVPrivateRun"), Value: aws.String(b.Worker.RunID)}, {Key: aws.String("CSVPrivateKind"), Value: aws.String("broker")}}}, nil
}
