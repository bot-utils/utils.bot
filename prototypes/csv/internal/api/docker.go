package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"utils.bot/csvprototype/internal/tabular"
)

var imagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_@-]{0,255}$`)

type Docker struct{ Image string }
type bounded struct {
	mu sync.Mutex
	bytes.Buffer
	cap      int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.cap - b.Len()
	if remaining > 0 {
		b.Buffer.Write(p[:min(remaining, n)])
	}
	if n > remaining {
		b.exceeded = true
		b.cancel()
	}
	return n, nil
}

func createArgs(image, name, job string) []string {
	return []string{
		"create", "--name", name, "--label", "utils.bot.csv.prototype=true", "--label", "utils.bot.csv.job=" + job,
		"--pull=never", "--network=none", "--ipc=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user=65532:65532", "--memory=512m", "--memory-swap=512m", "--cpus=1", "--pids-limit=64",
		"--ulimit", "core=0:0", "--log-driver=none", "--env", "GOMAXPROCS=1", "--env", "GOMEMLIMIT=384MiB",
		"--interactive", image, "--worker",
	}
}

func (d Docker) Run(ctx context.Context, job Job) (result tabular.Result, err error) {
	return d.run(ctx, job, "--worker")
}

// mode is test-only control of the bundled isolation probes. HTTP requests
// always enter Run and cannot supply a process argument or executable.
func (d Docker) run(ctx context.Context, job Job, mode string) (result tabular.Result, err error) {
	ctx, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	if !imagePattern.MatchString(d.Image) {
		return result, &tabular.Error{Code: "worker_unavailable", Status: 503}
	}
	image, e := resolveImage(ctx, d.Image)
	if e != nil {
		return result, &tabular.Error{Code: "worker_unavailable", Status: 503}
	}
	payload, e := json.Marshal(job)
	if e != nil || len(payload) > MaxWire {
		return result, &tabular.Error{Code: "request_limit", Status: 413}
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return result, &tabular.Error{Code: "worker_unavailable", Status: 503}
	}
	label := hex.EncodeToString(id[:])
	name := "utils-csv-" + label
	defer func() {
		if !cleanup(name, label) {
			result = tabular.Result{}
			err = &tabular.Error{Code: "worker_cleanup_failed", Status: 503}
		}
	}()
	// Creation has a detached, bounded context and gets NO input. Cancellation
	// cannot leave a job running while the caller loses its container identifier.
	createCtx, createCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	args := createArgs(image, name, label)
	args[len(args)-1] = mode
	created := exec.CommandContext(createCtx, "docker", args...)
	created.Stdout = io.Discard
	created.Stderr = io.Discard
	e = created.Run()
	createCancel()
	if e != nil {
		return result, &tabular.Error{Code: "worker_unavailable", Status: 503}
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(work, "docker", "start", "--attach", "--interactive", name)
	cmd.Stdin = bytes.NewReader(payload)
	output := &bounded{cap: tabular.MaxOutput + 4096, cancel: cancel}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	e = cmd.Run()
	if ctx.Err() != nil {
		code, status := "worker_timeout", 504
		if errors.Is(ctx.Err(), context.Canceled) {
			code, status = "request_cancelled", 408
		}
		return result, &tabular.Error{Code: code, Status: status}
	}
	if output.exceeded {
		return result, &tabular.Error{Code: "output_byte_limit", Status: 413}
	}
	if e != nil {
		status := inspect(name)
		if status.exists && status.oom {
			return result, &tabular.Error{Code: "worker_memory_limit", Status: 413}
		}
		return result, &tabular.Error{Code: "worker_unavailable", Status: 503}
	}
	var reply Reply
	dec := json.NewDecoder(bytes.NewReader(output.Bytes()))
	dec.DisallowUnknownFields()
	if dec.Decode(&reply) != nil {
		return result, &tabular.Error{Code: "invalid_worker_response", Status: 503}
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return result, &tabular.Error{Code: "invalid_worker_response", Status: 503}
	}
	if reply.Error != nil {
		if reply.Result != nil || !knownError(reply.Error) {
			return result, &tabular.Error{Code: "invalid_worker_response", Status: 503}
		}
		return result, reply.Error
	}
	if reply.Result == nil || !validResult(job.Operation, *reply.Result) {
		return result, &tabular.Error{Code: "invalid_worker_response", Status: 503}
	}
	return *reply.Result, nil
}
func knownError(e *tabular.Error) bool {
	valid := map[string]int{"invalid_csv": 400, "invalid_options": 400, "invalid_parts": 400, "unknown_operation": 400, "file_limit": 413, "column_limit": 413, "header_limit": 413, "cell_limit": 413, "row_limit": 413, "output_row_limit": 413, "output_byte_limit": 413, "options_limit": 413, "join_pair_limit": 413, "group_limit": 413, "invalid_header": 422, "invalid_columns": 422, "invalid_keep": 422, "invalid_join_type": 422, "invalid_prefix": 422, "output_column_collision": 422, "invalid_metrics": 422, "invalid_decimal": 422, "decimal_range": 422}
	return valid[e.Code] == e.Status && e.Status != 0
}
func validResult(op string, r tabular.Result) bool {
	if r.Operation != op || r.Rows == nil || len(r.Columns) == 0 || len(r.Columns) > 2*tabular.MaxColumns || r.OutputRows != len(r.Rows) || r.OutputRows > tabular.MaxRows {
		return false
	}
	if op == "aggregate" && r.OutputRows > tabular.MaxGroups {
		return false
	}
	expected := 1
	if op == "join" {
		expected = 2
	}
	if len(r.InputRows) != expected {
		return false
	}
	for k, n := range r.InputRows {
		if n < 0 || n > tabular.MaxRows || op != "join" && k != "file" || op == "join" && k != "left" && k != "right" {
			return false
		}
	}
	seen := map[string]bool{}
	for _, h := range r.Columns {
		if h == "" || len(h) > tabular.MaxHeader || seen[h] {
			return false
		}
		seen[h] = true
	}
	for _, row := range r.Rows {
		if len(row) != len(r.Columns) {
			return false
		}
		for _, cell := range row {
			if len(cell) > tabular.MaxCell {
				return false
			}
		}
	}
	encoded, e := json.Marshal(r)
	return e == nil && len(encoded) <= tabular.MaxOutput
}
func resolveImage(ctx context.Context, name string) (string, error) {
	check, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, e := exec.CommandContext(check, "docker", "image", "inspect", name).Output()
	if e != nil {
		return "", e
	}
	var info []struct {
		ID     string `json:"Id"`
		Config struct {
			Volumes    map[string]json.RawMessage
			Env        []string
			Entrypoint []string
			Cmd        []string
		}
	}
	if json.Unmarshal(out, &info) != nil || len(info) != 1 || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(info[0].ID) || len(info[0].Config.Volumes) != 0 || len(info[0].Config.Env) != 1 || info[0].Config.Env[0] != "PATH=/nonexistent" || len(info[0].Config.Cmd) != 0 || len(info[0].Config.Entrypoint) != 1 || info[0].Config.Entrypoint[0] != "/csv-prototype" {
		return "", errors.New("invalid worker image")
	}
	return info[0].ID, nil
}

type containerState struct{ known, exists, running, oom bool }

func inspect(name string) containerState {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Running}} {{.State.OOMKilled}}", name).CombinedOutput()
	if e != nil {
		message := strings.ToLower(string(out))
		if strings.Contains(message, "no such object") || strings.Contains(message, "no such container") {
			return containerState{known: true}
		}
		return containerState{}
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 {
		return containerState{}
	}
	return containerState{known: true, exists: true, running: fields[0] == "true", oom: fields[1] == "true"}
}
func cleanup(name, label string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Only this random-labelled job is eligible for pruning. No force deletion
	// of a running worker, broad prune, source mount or customer temporary file.
	_ = exec.CommandContext(ctx, "docker", "kill", name).Run()
	s := inspect(name)
	if !s.known || s.running {
		return false
	}
	if !s.exists {
		return true
	}
	cmd := exec.CommandContext(ctx, "docker", "container", "prune", "--force", "--filter", "label=utils.bot.csv.prototype=true", "--filter", "label=utils.bot.csv.job="+label)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return false
	}
	s = inspect(name)
	return s.known && !s.exists
}
