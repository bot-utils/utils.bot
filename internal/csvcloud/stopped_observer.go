package csvcloud

import (
	"context"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

type DescribeOnly interface {
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

// StoppedObserver's expected identities are fixed by the independently reviewed
// run config, never by the worker or the proof request. It has no Stop/Run API.
type StoppedObserver struct {
	Client                                         DescribeOnly `json:"-"`
	Cluster, TaskARN, Definition, Group, StartedBy string
}

func (s StoppedObserver) Observe(ctx context.Context) (string, []string, error) {
	if s.Client == nil || s.Cluster == "" || s.TaskARN == "" || s.Definition == "" || s.Group == "" || s.StartedBy == "" {
		return "", nil, ErrInvalid
	}
	result, e := s.Client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(s.Cluster), Tasks: []string{s.TaskARN}}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if e != nil || result == nil || len(result.Failures) != 0 || len(result.Tasks) != 1 {
		return "", nil, ErrCleanup
	}
	t := result.Tasks[0]
	if aws.ToString(t.TaskArn) != s.TaskARN || aws.ToString(t.ClusterArn) != s.Cluster || aws.ToString(t.TaskDefinitionArn) != s.Definition || aws.ToString(t.Group) != s.Group || aws.ToString(t.StartedBy) != s.StartedBy || aws.ToString(t.LastStatus) != "STOPPED" {
		return "", nil, ErrCleanup
	}
	var ids []string
	for _, a := range t.Attachments {
		if aws.ToString(a.Type) != "ElasticNetworkInterface" {
			continue
		}
		for _, v := range a.Details {
			if aws.ToString(v.Name) == "networkInterfaceId" {
				id := aws.ToString(v.Value)
				if !regexp.MustCompile(`^eni-([a-f0-9]{8}|[a-f0-9]{17})$`).MatchString(id) {
					return "", nil, ErrCleanup
				}
				ids = append(ids, id)
			}
		}
	}
	if !interfaceIDs(ids) {
		return "", nil, ErrCleanup
	}
	return s.TaskARN, ids, nil
}
