package csvcloud

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"reflect"
	"regexp"
	"strings"
)

// WireReview is an explicit synthetic-only exception to the default single
// container/no-Secrets profile. The secret ARN holds only this run's TLS identity.
type WireReview struct {
	Account, RunID, Image, ExecutionRole, SecretARN string
	SyntheticOnly                                   bool
}

func (w WireReview) valid() bool {
	return w.SyntheticOnly && regexp.MustCompile(`^[0-9]{12}$`).MatchString(w.Account) && opaque(w.RunID) && w.ExecutionRole == "arn:aws:iam::"+w.Account+":role/utils-bot-csv-private-"+w.RunID[:16]+"-worker-execution" && w.SecretARN == "arn:aws:ssm:us-east-2:"+w.Account+":parameter/utils-bot/csv-private/"+w.RunID+"/tls" && strings.HasPrefix(w.Image, w.Account+".dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-private@sha256:") && opaque(strings.TrimPrefix(w.Image, w.Account+".dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-private@sha256:"))
}
func (w WireReview) Definition() (et.TaskDefinition, error) {
	if !w.valid() {
		return et.TaskDefinition{}, ErrInvalid
	}
	base := func(name, user, mode string) et.ContainerDefinition {
		return et.ContainerDefinition{Name: aws.String(name), Image: aws.String(w.Image), User: aws.String(user), Essential: aws.Bool(false), Privileged: aws.Bool(false), ReadonlyRootFilesystem: aws.Bool(true), Command: []string{"--mode", mode}, StopTimeout: aws.Int32(30), MountPoints: []et.MountPoint{{SourceVolume: aws.String("exchange"), ContainerPath: aws.String("/exchange"), ReadOnly: aws.Bool(false)}}, LinuxParameters: &et.LinuxParameters{Capabilities: &et.KernelCapabilities{Drop: []string{"ALL"}}}, Ulimits: []et.Ulimit{{Name: et.UlimitNameCore, SoftLimit: 0, HardLimit: 0}, {Name: et.UlimitNameNofile, SoftLimit: 128, HardLimit: 128}}}
	}
	init := base("fifo-init", "0:0", "fifo-init")
	init.LinuxParameters.Capabilities.Drop = []string{"AUDIT_WRITE", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
	parser := base("parser", "65533:65533", "parser")
	transport := base("transport", "65532:65532", "transport")
	transport.Essential = aws.Bool(true)
	transport.Secrets = []et.Secret{{Name: aws.String("CSV_TLS_BOOTSTRAP"), ValueFrom: aws.String(w.SecretARN)}}
	transport.PortMappings = []et.PortMapping{{ContainerPort: aws.Int32(8443), Protocol: et.TransportProtocolTcp}}
	for _, c := range []*et.ContainerDefinition{&parser, &transport} {
		c.DependsOn = []et.ContainerDependency{{ContainerName: aws.String("fifo-init"), Condition: et.ContainerConditionSuccess}}
	}
	// Omitting ephemeralStorage retains Fargate 1.4.0 default 20 GiB.
	return et.TaskDefinition{Family: aws.String("utils-bot-csv-private-" + w.RunID[:16] + "-worker"), ExecutionRoleArn: aws.String(w.ExecutionRole), NetworkMode: et.NetworkModeAwsvpc, RequiresCompatibilities: []et.Compatibility{et.CompatibilityFargate}, Cpu: aws.String("1024"), Memory: aws.String("2048"), RuntimePlatform: &et.RuntimePlatform{CpuArchitecture: et.CPUArchitectureArm64, OperatingSystemFamily: et.OSFamilyLinux}, Volumes: []et.Volume{{Name: aws.String("exchange")}}, ContainerDefinitions: []et.ContainerDefinition{init, parser, transport}}, nil
}

// Validate accepts only the complete expected security profile. Provider-owned
// registration metadata is excluded; the Runner separately pins the full hash.
func (w WireReview) Validate(d *et.TaskDefinition) error {
	expected, e := w.Definition()
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

// Registration includes mandatory tags in the create request. IAM restricts
// both the family/kind relationship and Fargate/CPU/memory/privilege fields.
func (w WireReview) Registration() (*ecs.RegisterTaskDefinitionInput, error) {
	d, e := w.Definition()
	if e != nil {
		return nil, e
	}
	return &ecs.RegisterTaskDefinitionInput{Family: d.Family, ExecutionRoleArn: d.ExecutionRoleArn, NetworkMode: d.NetworkMode, ContainerDefinitions: d.ContainerDefinitions, Volumes: d.Volumes, Cpu: d.Cpu, Memory: d.Memory, RuntimePlatform: d.RuntimePlatform, RequiresCompatibilities: d.RequiresCompatibilities, Tags: []et.Tag{{Key: aws.String("CSVPrivateRun"), Value: aws.String(w.RunID)}, {Key: aws.String("CSVPrivateKind"), Value: aws.String("worker")}}}, nil
}
