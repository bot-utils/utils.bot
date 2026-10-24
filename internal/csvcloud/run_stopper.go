package csvcloud

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"time"
)

// RunStopper is controller-only and pins both original tasks. It never lists,
// launches, replaces or chooses tasks supplied in an untrusted event. Success
// requires BOTH pinned tasks STOPPED plus fresh authenticated absence evidence
// for EACH exact ECS-observed ENI from the independent verifier. StopTask or
// STOPPED alone is insufficient; missing/contradictory IDs or proof fail closed.
type RunStopper struct {
	BrokerNeverStarted func(context.Context) error
	Client             LifecycleAPI
	Worker, Broker     StoppedObserver
	Verify             func(context.Context, StoppedObserver, []string) error
}

func (r RunStopper) Stop(ctx context.Context, j Job) error {
	if r.Client == nil || r.Verify == nil || j.Dispatch == nil || r.Worker.TaskARN != j.Dispatch.TaskARN || r.Worker.StartedBy != j.Dispatch.Token[:32] || r.Worker.Group != "csv-"+j.Dispatch.Token || r.Worker.TaskARN == r.Broker.TaskARN {
		return ErrCleanup
	}
	scopes := []StoppedObserver{r.Worker}
	if r.Broker.TaskARN == "" {
		if r.BrokerNeverStarted == nil || r.BrokerNeverStarted(ctx) != nil {
			return ErrCleanup
		}
	} else {
		scopes = append(scopes, r.Broker)
	}
	for _, scope := range scopes {
		if scope.TaskARN == "" || scope.Cluster == "" || scope.Definition == "" || scope.StartedBy == "" || scope.Group == "" {
			return ErrCleanup
		}
		observe := func() (et.Task, error) {
			v, e := r.Client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(scope.Cluster), Tasks: []string{scope.TaskARN}}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
			if e != nil || v == nil || len(v.Failures) != 0 || len(v.Tasks) != 1 {
				return et.Task{}, ErrCleanup
			}
			t := v.Tasks[0]
			if aws.ToString(t.TaskArn) != scope.TaskARN || aws.ToString(t.ClusterArn) != scope.Cluster || aws.ToString(t.TaskDefinitionArn) != scope.Definition || aws.ToString(t.StartedBy) != scope.StartedBy || aws.ToString(t.Group) != scope.Group {
				return et.Task{}, ErrCleanup
			}
			return t, nil
		}
		t, e := observe()
		if e != nil {
			return e
		}
		if aws.ToString(t.LastStatus) != "STOPPED" {
			_, e = r.Client.StopTask(ctx, &ecs.StopTaskInput{Cluster: aws.String(scope.Cluster), Task: aws.String(scope.TaskARN), Reason: aws.String("private CSV controller writer fence")}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
			if e != nil {
				return ErrCleanup
			}
		}
		for {
			t, e = observe()
			if e != nil {
				return e
			}
			if aws.ToString(t.LastStatus) == "STOPPED" {
				break
			}
			select {
			case <-ctx.Done():
				return ErrCleanup
			case <-time.After(100 * time.Millisecond):
			}
		}
		scope.Client = r.Client
		_, ids, e := scope.Observe(ctx)
		if e != nil || r.Verify(ctx, scope, ids) != nil {
			return ErrCleanup
		}
	}
	return nil
}
