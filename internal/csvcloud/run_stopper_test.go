package csvcloud

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"strings"
	"testing"
	"time"
)

type stopPair struct {
	tasks       map[string]et.Task
	stops       int
	stayRunning bool
}

func (s *stopPair) DescribeTasks(_ context.Context, q *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{Tasks: []et.Task{s.tasks[q.Tasks[0]]}}, nil
}
func (s *stopPair) StopTask(_ context.Context, q *ecs.StopTaskInput, _ ...func(*ecs.Options)) (*ecs.StopTaskOutput, error) {
	s.stops++
	t := s.tasks[*q.Task]
	if !s.stayRunning {
		t.LastStatus = aws.String("STOPPED")
		s.tasks[*q.Task] = t
	}
	return &ecs.StopTaskOutput{Task: &t}, nil
}
func stopperFixture() (RunStopper, Job, *stopPair) {
	w, d, f, _ := workerFixture()
	worker := StoppedObserver{Cluster: w.Cluster, TaskARN: d.TaskARN, Definition: w.Definition, Group: "csv-" + d.Token, StartedBy: d.Token[:32]}
	broker := worker
	broker.TaskARN += "b"
	broker.Group = "csv-broker-" + strings.Repeat("c", 64)
	t := f.task
	t.TaskArn = aws.String(broker.TaskARN)
	t.Group = aws.String(broker.Group)
	pair := &stopPair{tasks: map[string]et.Task{worker.TaskARN: f.task, broker.TaskARN: t}}
	return RunStopper{Client: pair, Worker: worker, Broker: broker, Verify: func(context.Context, StoppedObserver, []string) error { return nil }}, Job{Dispatch: &d}, pair
}
func TestRunStopperRequiresBothOriginalTasksAndEachENIProof(t *testing.T) {
	for _, scenario := range []string{"ok", "foreign", "missing_eni", "multiple_eni", "worker_proof", "broker_proof", "stop_not_stopped"} {
		t.Run(scenario, func(t *testing.T) {
			r, j, s := stopperFixture()
			proofs := 0
			r.Verify = func(_ context.Context, scope StoppedObserver, ids []string) error {
				proofs++
				if len(ids) != 1 {
					t.Fatal("unbounded IDs")
				}
				if scenario == "worker_proof" && scope.TaskARN == r.Worker.TaskARN || scenario == "broker_proof" && scope.TaskARN == r.Broker.TaskARN {
					return ErrCleanup
				}
				return nil
			}
			tsk := s.tasks[r.Worker.TaskARN]
			switch scenario {
			case "foreign":
				tsk.Group = aws.String("foreign")
			case "missing_eni":
				tsk.Attachments = nil
			case "multiple_eni":
				tsk.Attachments = append(tsk.Attachments, tsk.Attachments[0])
			case "stop_not_stopped":
				s.stayRunning = true
			}
			s.tasks[r.Worker.TaskARN] = tsk
			bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			e := r.Stop(bounded, j)
			if (e == nil) != (scenario == "ok") {
				t.Fatal("unverified writer fence", e)
			}
			if scenario == "ok" && (s.stops != 2 || proofs != 2) {
				t.Fatal("not both tasks verified")
			}
			if scenario == "foreign" && s.stops != 0 {
				t.Fatal("foreign task stopped")
			}
		})
	}
}
