package csvcloud

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	et "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"strings"
	"testing"
)

func privateReview() WireReview {
	run := strings.Repeat("a", 64)
	account := "123456789012"
	return WireReview{Account: account, RunID: run, Image: account + ".dkr.ecr.us-east-2.amazonaws.com/utils-bot-csv-private@sha256:" + strings.Repeat("b", 64), ExecutionRole: "arn:aws:iam::" + account + ":role/utils-bot-csv-private-" + run[:16] + "-worker-execution", SecretARN: "arn:aws:ssm:us-east-2:" + account + ":parameter/utils-bot/csv-private/" + run + "/tls", SyntheticOnly: true}
}
func TestPrivateDefinitionRejectsSecurityDrift(t *testing.T) {
	w := privateReview()
	definition, e := w.Definition()
	if e != nil || w.Validate(&definition) != nil {
		t.Fatal("expected private profile rejected")
	}
	for name, mutate := range map[string]func(*et.TaskDefinition){
		"extra_storage": func(d *et.TaskDefinition) { d.EphemeralStorage = &et.EphemeralStorage{SizeInGiB: 21} },
		"task_role":     func(d *et.TaskDefinition) { d.TaskRoleArn = aws.String("arn:aws:iam::123456789012:role/credentialed") },
		"shared_pid":    func(d *et.TaskDefinition) { d.PidMode = et.PidModeTask },
		"extra_container": func(d *et.TaskDefinition) {
			d.ContainerDefinitions = append(d.ContainerDefinitions, d.ContainerDefinitions[1])
		},
		"parser_secret": func(d *et.TaskDefinition) { d.ContainerDefinitions[1].Secrets = d.ContainerDefinitions[2].Secrets },
		"extra_port": func(d *et.TaskDefinition) {
			d.ContainerDefinitions[1].PortMappings = d.ContainerDefinitions[2].PortMappings
		},
		"transport_env": func(d *et.TaskDefinition) {
			d.ContainerDefinitions[2].Environment = []et.KeyValuePair{{Name: aws.String("CSV_TLS_BOOTSTRAP"), Value: aws.String("forbidden")}}
		},
		"parser_root": func(d *et.TaskDefinition) { d.ContainerDefinitions[1].User = aws.String("0:0") },
		"parser_caps": func(d *et.TaskDefinition) {
			d.ContainerDefinitions[1].LinuxParameters.Capabilities.Add = []string{"SYS_PTRACE"}
		},
		"init_extra_cap": func(d *et.TaskDefinition) { d.ContainerDefinitions[0].LinuxParameters.Capabilities.Drop = nil },
		"writable_root":  func(d *et.TaskDefinition) { d.ContainerDefinitions[1].ReadonlyRootFilesystem = aws.Bool(false) },
		"logging_sink": func(d *et.TaskDefinition) {
			d.ContainerDefinitions[2].LogConfiguration = &et.LogConfiguration{LogDriver: et.LogDriverAwslogs}
		},
		"secret_scope": func(d *et.TaskDefinition) { d.ContainerDefinitions[2].Secrets[0].ValueFrom = aws.String("another-run") },
		"image_drift":  func(d *et.TaskDefinition) { d.ContainerDefinitions[1].Image = aws.String("unpinned:latest") },
		"extra_volume": func(d *et.TaskDefinition) { d.Volumes = append(d.Volumes, et.Volume{Name: aws.String("foreign")}) },
		"wrong_arch":   func(d *et.TaskDefinition) { d.RuntimePlatform.CpuArchitecture = et.CPUArchitectureX8664 },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(definition)
			var d et.TaskDefinition
			_ = json.Unmarshal(raw, &d)
			mutate(&d)
			if w.Validate(&d) == nil {
				t.Fatal("security drift accepted")
			}
		})
	}
	w.SyntheticOnly = false
	if _, e = w.Definition(); e == nil {
		t.Fatal("production profile unexpectedly accepted")
	}
}
func TestPrivateRequestContainsNoJobOrTLSOverride(t *testing.T) {
	r := Runner{Wire: func() *WireReview { w := privateReview(); return &w }()}
	j := Job{ID: strings.Repeat("d", 64), Dispatch: &Dispatch{Token: strings.Repeat("c", 64)}}
	q := r.request(j)
	if q.Overrides != nil {
		t.Fatal("private metadata override")
	}
	raw, _ := json.Marshal(q)
	if strings.Contains(string(raw), j.ID) || strings.Contains(string(raw), "BOOTSTRAP") {
		t.Fatal("job or identity exposed")
	}
}

func TestProviderDefaultsValidateWithoutMutatingPinnedDefinition(t *testing.T) {
	w := privateReview()
	worker, _ := w.Definition()
	broker, _ := (BrokerReview{Worker: w, Image: w.Image}).Definition()
	for kind, original := range map[string]et.TaskDefinition{"worker": worker, "broker": broker} {
		raw, _ := json.Marshal(original)
		var d et.TaskDefinition
		_ = json.Unmarshal(raw, &d)
		d.PlacementConstraints = []et.TaskDefinitionPlacementConstraint{}
		if len(d.Volumes) == 0 {
			d.Volumes = []et.Volume{}
		}
		for i := range d.Volumes {
			d.Volumes[i].Host = &et.HostVolumeProperties{}
		}
		for i := range d.ContainerDefinitions {
			c := &d.ContainerDefinitions[i]
			if len(c.Environment) == 0 {
				c.Environment = []et.KeyValuePair{}
			}
			c.SystemControls = []et.SystemControl{}
			c.VolumesFrom = []et.VolumeFrom{}
			if len(c.MountPoints) == 0 {
				c.MountPoints = []et.MountPoint{}
			}
			if len(c.PortMappings) == 0 {
				c.PortMappings = []et.PortMapping{}
			}
			for j := range c.PortMappings {
				c.PortMappings[j].HostPort = c.PortMappings[j].ContainerPort
			}
			c.LinuxParameters.Capabilities.Add = []string{}
		}
		before, _ := json.Marshal(d)
		validate := w.Validate
		if kind == "broker" {
			validate = (BrokerReview{Worker: w, Image: w.Image}).Validate
		}
		if validate(&d) != nil {
			t.Fatal("legitimate defaults rejected", kind)
		}
		after, _ := json.Marshal(d)
		if string(before) != string(after) {
			t.Fatal("hash-pinned source mutated")
		}
		d.ContainerDefinitions[0].Environment = []et.KeyValuePair{{Name: aws.String("UNAPPROVED"), Value: aws.String("value")}}
		if validate(&d) == nil {
			t.Fatal("environment drift hidden", kind)
		}
	}
}
