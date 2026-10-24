package csvcloud

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in local Linux check: no network, cloud credentials, input files or jobs.
func TestPrivateLocalBrokerStartupWithoutNetwork(t *testing.T) {
	image := os.Getenv("CSV_PRIVATE_LOCAL_BROKER_DIAG_IMAGE")
	if image == "" {
		t.Skip("explicit local diagnostic image required")
	}
	if !strings.HasPrefix(image, "sha256:") || !opaque(strings.TrimPrefix(image, "sha256:")) {
		t.Fatal("immutable local image required")
	}
	b := brokerStageFixture(t)
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CSV_BROKER_BOOTSTRAP=" + string(raw)}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "docker", append([]string{"--context", "colima"}, args...)...)
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	label := "utils.bot.csv.local_probe=" + b.RunID
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cleanup, "docker", "--context", "colima", "container", "prune", "--force", "--filter", "label="+label)
		cmd.Env = env
		if _, e := cmd.CombinedOutput(); e != nil {
			t.Error("local container cleanup unconfirmed")
		}
	}()
	name := "csv-local-broker-" + b.RunID[:16]
	_, e = run("create", "--pull", "never", "--name", name, "--label", label, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532", "--cpus", "1", "--memory", "512m", "--pids-limit", "64", "-e", "AWS_REGION=us-east-2", "-e", "AWS_ACCESS_KEY_ID=test", "-e", "AWS_SECRET_ACCESS_KEY=test", "-e", "CSV_BROKER_BOOTSTRAP", image, "--synthetic-run")
	if e != nil {
		t.Fatal("local container creation failed")
	}
	out, e := run("inspect", "--format", "{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{.Config.User}}", name)
	if e != nil || strings.TrimSpace(string(out)) != "none true 65532:65532" {
		t.Fatal("local isolation differs")
	}
	_, _ = run("start", "--attach", name)
	out, e = run("inspect", "--format", "{{.State.ExitCode}}", name)
	if e != nil {
		t.Fatal("local exit unconfirmed")
	}
	code, e := strconv.Atoi(strings.TrimSpace(string(out)))
	if e != nil || code != 84 {
		t.Fatalf("local startup exited at fixed stage %d, expected blocked metadata stage 84", code)
	}
	out, e = run("logs", name)
	if e != nil || len(out) != 0 {
		t.Fatal("unexpected local runtime output")
	}
	t.Log("LOCAL_BROKER_STARTUP_VERIFIED hardening/bootstrap/config passed; metadata blocked by network-none; no runtime output or cloud call")
}
