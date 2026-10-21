package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func dockerTests(t *testing.T) Docker {
	t.Helper()
	if os.Getenv("CSV_DOCKER_TESTS") != "1" {
		t.Skip("set CSV_DOCKER_TESTS=1 after scripts/build.sh")
	}
	return Docker{Image: "utils-bot-csv-prototype:local"}
}
func assertNoJobs(t *testing.T) {
	t.Helper()
	out, e := exec.Command("docker", "ps", "--all", "--filter", "label=utils.bot.csv.prototype=true", "--format", "{{.Names}}").Output()
	if e != nil || len(strings.TrimSpace(string(out))) != 0 {
		t.Fatal("prototype worker survived cleanup", string(out), e)
	}
}

func TestDockerActualWorkerAndCleanup(t *testing.T) {
	d := dockerTests(t)
	assertNoJobs(t)
	for _, j := range []Job{
		{Operation: "dedupe", Options: json.RawMessage(`{"key_columns":["id"],"keep":"last"}`), Inputs: map[string][]byte{"file": []byte("id,v\nx,old\nx,new\n")}},
		{Operation: "join", Options: json.RawMessage(`{"left_key_columns":["id"],"right_key_columns":["key"],"type":"anti"}`), Inputs: map[string][]byte{"left": []byte("id\na\nb\n"), "right": []byte("key\na\n")}},
		{Operation: "aggregate", Options: json.RawMessage(`{"metrics":[{"name":"sum","op":"sum","column":"amount"}]}`), Inputs: map[string][]byte{"file": []byte("amount\n0.1\n0.2\n")}},
	} {
		r, e := d.Run(context.Background(), j)
		if e != nil || r.OutputRows != 1 {
			t.Fatal(r, e)
		}
		assertNoJobs(t)
	}
	j := Job{Operation: "dedupe", Options: json.RawMessage(`{"instructions":"PRIVATE_CANARY"}`), Inputs: map[string][]byte{"file": []byte("id\nPRIVATE_INPUT\n")}}
	_, e := d.Run(context.Background(), j)
	if e == nil || e.Error() != "invalid_options" {
		t.Fatal(e)
	}
	assertNoJobs(t)
}

func TestDockerKernelIsolationAndNoCredentials(t *testing.T) {
	d := dockerTests(t)
	t.Setenv("CSV_PRIVATE_CANARY", "do-not-forward")
	image, e := resolveImage(context.Background(), d.Image)
	if e != nil {
		t.Fatal(e)
	}
	label := fmt.Sprintf("probe%d", time.Now().UnixNano())
	name := "utils-csv-" + label
	defer func() {
		if !cleanup(name, label) {
			t.Error("probe cleanup failed")
		}
	}()
	args := createArgs(image, name, label)
	args[len(args)-1] = "--probe-isolation"
	if out, e := exec.Command("docker", args...).CombinedOutput(); e != nil {
		t.Fatal(string(out), e)
	}
	out, e := exec.Command("docker", "start", "--attach", name).Output()
	if e != nil {
		t.Fatal(e)
	}
	var state struct {
		NetworkDenied           bool   `json:"network_denied"`
		WriteDenied             bool   `json:"write_denied"`
		SharedMemoryWriteDenied bool   `json:"shared_memory_write_denied"`
		UID                     int    `json:"uid"`
		CredentialAbsent        bool   `json:"credential_absent"`
		Memory                  string `json:"memory_max"`
		CPU                     string `json:"cpu_max"`
	}
	if json.Unmarshal(out, &state) != nil || !state.NetworkDenied || !state.WriteDenied || !state.SharedMemoryWriteDenied || !state.CredentialAbsent || state.UID != 65532 || state.Memory != "536870912" || state.CPU != "100000 100000" {
		t.Fatal(string(out))
	}
	out, e = exec.Command("docker", "inspect", "--format", "{{json .HostConfig}}", name).Output()
	if e != nil {
		t.Fatal(e)
	}
	var host struct {
		NetworkMode                  string
		IpcMode                      string
		ReadonlyRootfs               bool
		Binds                        []string
		Memory, MemorySwap, NanoCpus int64
		CapDrop                      []string
		LogConfig                    struct{ Type string }
	}
	if json.Unmarshal(out, &host) != nil || host.NetworkMode != "none" || host.IpcMode != "none" || !host.ReadonlyRootfs || len(host.Binds) != 0 || host.Memory != 512<<20 || host.MemorySwap != 512<<20 || host.NanoCpus != 1_000_000_000 || host.LogConfig.Type != "none" {
		t.Fatal("kernel controls missing")
	}
}

func TestDockerTimeoutCancellationAndMemoryKill(t *testing.T) {
	d := dockerTests(t)
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		if cancelled {
			var stop context.CancelFunc
			ctx, stop = context.WithCancel(ctx)
			defer stop()
			go func() { time.Sleep(time.Second); stop() }()
		}
		started := time.Now()
		_, e := d.run(ctx, Job{}, "--probe-wait")
		cancel()
		want := "worker_timeout"
		if cancelled {
			want = "request_cancelled"
		}
		if e == nil || e.Error() != want || time.Since(started) > 12*time.Second {
			t.Fatal("worker did not stop", e)
		}
		assertNoJobs(t)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, e := d.run(ctx, Job{}, "--probe-memory")
	if e == nil || e.Error() != "worker_memory_limit" {
		t.Fatal("memory cap did not fail closed", e)
	}
	assertNoJobs(t)
}
