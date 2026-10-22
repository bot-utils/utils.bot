package csvcloud

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// LifecycleAPI is supplied with per-run IAM credentials scoped to the original
// task ARN and cluster. It deliberately has no RunTask or object/payment API.
type LifecycleAPI interface {
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	StopTask(context.Context, *ecs.StopTaskInput, ...func(*ecs.Options)) (*ecs.StopTaskOutput, error)
}

// NetworkGone must be backed by a separate short-lived verifier identity. EC2
// DescribeNetworkInterfaces has region-wide IAM scope; its credentials must not
// enter the data/payment broker. The verifier accepts only ECS-observed IDs.
// No default implementation silently reuses broker credentials.
type NetworkGone interface {
	VerifyAbsent(context.Context, []string) error
}

type PrivateWorker struct {
	Review                                      *WireReview
	Client                                      LifecycleAPI
	Verifier                                    NetworkGone
	Cluster, Definition, Subnet, DefinitionHash string
	Prefix                                      netip.Prefix
	TLS                                         *tls.Config
	Gate                                        Gate
}

func (w PrivateWorker) valid(d Dispatch) bool {
	return w.Gate.Enabled && w.Review != nil && w.Client != nil && w.Verifier != nil && w.TLS != nil && !w.TLS.InsecureSkipVerify && w.TLS.RootCAs != nil && w.TLS.ServerName == "csv-worker" && w.TLS.MinVersion == tls.VersionTLS13 && w.TLS.MaxVersion == tls.VersionTLS13 && len(w.TLS.Certificates) == 1 && len(w.TLS.NextProtos) == 1 && w.TLS.NextProtos[0] == "utilsbot-csv/1" && opaque(d.Token) && opaque(w.DefinitionHash) && w.Prefix.IsValid() && w.Prefix.Addr().IsPrivate() && w.Prefix.Bits() >= 24 && w.Subnet != "" && strings.Contains(w.Cluster, ":ecs:us-east-2:") && strings.Contains(w.Cluster, ":cluster/") && strings.HasPrefix(d.TaskARN, strings.Replace(w.Cluster, ":cluster/", ":task/", 1)+"/") && strings.Contains(w.Definition, ":task-definition/")
}
func (w PrivateWorker) task(ctx context.Context, d Dispatch) (et.Task, error) {
	if !w.valid(d) {
		return et.Task{}, ErrInvalid
	}
	out, e := w.Client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(w.Cluster), Tasks: []string{d.TaskARN}}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if e != nil || out == nil || len(out.Failures) != 0 || len(out.Tasks) != 1 {
		return et.Task{}, ErrUnknown
	}
	t := out.Tasks[0]
	if aws.ToString(t.TaskArn) != d.TaskARN || aws.ToString(t.ClusterArn) != w.Cluster || aws.ToString(t.TaskDefinitionArn) != w.Definition || aws.ToString(t.Group) != "csv-"+d.Token || aws.ToString(t.StartedBy) != d.Token[:32] || t.EnableExecuteCommand || t.LaunchType != et.LaunchTypeFargate || aws.ToString(t.PlatformVersion) != "1.4.0" {
		return et.Task{}, ErrIntegrity
	}
	// The complete task definition was independently pinned by Runner before
	// dispatch. No command, environment, role or resource override is permitted.
	if t.Overrides != nil {
		overrides := *t.Overrides
		seen := map[string]bool{}
		for _, c := range overrides.ContainerOverrides {
			name := aws.ToString(c.Name)
			if (name != "fifo-init" && name != "parser" && name != "transport") || seen[name] || !reflect.DeepEqual(c, et.ContainerOverride{Name: c.Name}) {
				return et.Task{}, ErrIntegrity
			}
			seen[name] = true
		}
		overrides.ContainerOverrides = nil
		if !reflect.DeepEqual(overrides, et.TaskOverride{}) {
			return et.Task{}, ErrIntegrity
		}
	}
	definition, e := w.Client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(w.Definition)}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
	if e != nil || definition == nil || definition.TaskDefinition == nil {
		return et.Task{}, ErrUnknown
	}
	raw, _ := json.Marshal(definition.TaskDefinition)
	if Hash(raw) != w.DefinitionHash || aws.ToString(definition.TaskDefinition.TaskDefinitionArn) != w.Definition || w.Review.Validate(definition.TaskDefinition) != nil {
		return et.Task{}, ErrIntegrity
	}

	return t, nil
}
func endpoint(t et.Task, subnet string, prefix netip.Prefix) (string, []string, error) {
	var ip, eni string
	count := 0
	for _, a := range t.Attachments {
		if aws.ToString(a.Type) != "ElasticNetworkInterface" {
			continue
		}
		count++
		values := map[string]string{}
		for _, v := range a.Details {
			k := aws.ToString(v.Name)
			if _, exists := values[k]; exists {
				return "", nil, ErrIntegrity
			}
			values[k] = aws.ToString(v.Value)
		}
		if values["subnetId"] != subnet || !strings.HasPrefix(values["networkInterfaceId"], "eni-") {
			return "", nil, ErrIntegrity
		}
		ip, eni = values["privateIPv4Address"], values["networkInterfaceId"]
	}
	address, e := netip.ParseAddr(ip)
	if count != 1 || e != nil || !address.Is4() || !address.IsPrivate() || !prefix.Contains(address) {
		return "", nil, ErrIntegrity
	}
	return net.JoinHostPort(address.String(), "8443"), []string{eni}, nil
}

// Session performs one connection to the original ECS-observed private IP.
// It never retries, resolves customer hostnames, fetches URLs or selects tasks.
func (w PrivateWorker) Session() MTLSWorker {
	return MTLSWorker{Connect: func(ctx context.Context, d Dispatch) (*tls.Conn, error) {
		t, e := w.task(ctx, d)
		if e != nil {
			return nil, e
		}
		if aws.ToString(t.LastStatus) != "RUNNING" {
			return nil, ErrUnknown
		}
		address, _, e := endpoint(t, w.Subnet, w.Prefix)
		if e != nil {
			return nil, e
		}
		c, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", address)
		if e != nil {
			return nil, ErrUnknown
		}
		return tls.Client(c, w.TLS.Clone()), nil
	}, Stopped: w.StopAndVerify}
}

// StopAndVerify is idempotent only for stopping/observation, never dispatch.
// A missing attachment or uncertain verifier response prevents publication.
func (w PrivateWorker) StopAndVerify(ctx context.Context, d Dispatch) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	t, e := w.task(ctx, d)
	if e != nil {
		return e
	}
	_, ids, e := endpoint(t, w.Subnet, w.Prefix)
	if e != nil {
		return e
	}
	if aws.ToString(t.LastStatus) != "STOPPED" {
		out, e := w.Client.StopTask(ctx, &ecs.StopTaskInput{Cluster: aws.String(w.Cluster), Task: aws.String(d.TaskARN), Reason: aws.String("private CSV single-use session complete")}, func(o *ecs.Options) { o.RetryMaxAttempts = 1 })
		if e != nil || out == nil || out.Task == nil || aws.ToString(out.Task.TaskArn) != d.TaskARN {
			return ErrCleanup
		}
	}
	for {
		t, e = w.task(ctx, d)
		if e != nil {
			return ErrCleanup
		}
		if aws.ToString(t.LastStatus) == "STOPPED" {
			break
		}
		select {
		case <-ctx.Done():
			return ErrCleanup
		case <-time.After(250 * time.Millisecond):
		}
	}
	if w.Verifier.VerifyAbsent(ctx, ids) != nil {
		return ErrCleanup
	}
	return nil
}
