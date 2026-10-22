package csvwire

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Opt-in, synthetic-only ARM64 Linux validation. The caller builds the exact
// static worker image; no AWS APIs, credentials, public route or payment occurs.
func TestPrivateDockerContainers(t *testing.T) {
	image, host := os.Getenv("CSV_PRIVATE_IMAGE"), os.Getenv("CSV_PRIVATE_DOCKER_HOST")
	if image == "" || host == "" {
		t.Skip("explicit local private-worker image and daemon required")
	}
	if !strings.HasPrefix(image, "sha256:") || len(image) != 71 || !strings.HasPrefix(host, "unix://") {
		t.Fatal("pinned local image required")
	}
	check := exec.Command("docker", "--host", host, "image", "inspect", "--format", "{{.Architecture}} {{.Os}}", image)
	architecture, e := check.Output()
	if e != nil || strings.TrimSpace(string(architecture)) != "arm64 linux" {
		t.Fatal("reviewed ARM64 Linux image required")
	}
	cases := []struct {
		op, options, expected string
		files                 map[string]string
	}{
		{"dedupe", `{"key_columns":["id"],"keep":"first"}`, "id,v\n1,a\n2,c\n", map[string]string{"file": "id,v\n1,a\n1,b\n2,c\n"}},
		{"join", `{"left_key_columns":["id"],"right_key_columns":["id"],"type":"inner"}`, "id,v,x\n1,a,z\n", map[string]string{"left": "id,v\n1,a\n2,b\n", "right": "id,x\n1,z\n"}},
		{"aggregate", `{"group_columns":["id"],"metrics":[{"op":"count_rows","name":"n"}]}`, "id,n\n1,2\n", map[string]string{"file": "id,v\n1,a\n1,b\n"}},
		{"transform", `{"column":"v","op":"upper"}`, "id,v\n1,HELLO\n", map[string]string{"file": "id,v\n1,hello\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			label := "utils.bot.csv.private.test=" + fmt.Sprint(time.Now().UnixNano())
			prefix := "csv-private-" + fmt.Sprint(time.Now().UnixNano())
			var containers []string
			command := func(args ...string) ([]byte, error) {
				cmd := exec.CommandContext(ctx, "docker", append([]string{"--host", host}, args...)...)
				return cmd.Output()
			}
			must := func(args ...string) []byte {
				b, e := command(args...)
				if e != nil {
					t.Fatalf("local docker %s failed", args[0])
				}
				return b
			}
			t.Cleanup(func() {
				cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
				defer done()
				run := func(args ...string) []byte {
					b, e := exec.CommandContext(cleanup, "docker", append([]string{"--host", host}, args...)...).Output()
					if e != nil {
						t.Errorf("owned docker cleanup %s failed", args[0])
					}
					return b
				}
				for _, c := range containers {
					run("stop", "--time", "1", c)
					if strings.TrimSpace(string(run("inspect", "--format", "{{.State.Running}}", c))) != "false" {
						t.Error("owned container still running")
					}
				}
				run("container", "prune", "--force", "--filter", "label="+label)
				run("volume", "prune", "--all", "--force", "--filter", "label="+label)
				run("network", "prune", "--force", "--filter", "label="+label)
				if len(bytes.TrimSpace(run("ps", "--all", "--quiet", "--filter", "label="+label))) != 0 {
					t.Error("owned container cleanup incomplete")
				}
				for _, kind := range []string{"volume", "network"} {
					if len(bytes.TrimSpace(run(kind, "ls", "--quiet", "--filter", "label="+label))) != 0 {
						t.Error("owned test resource remains")
					}
				}
			})
			volume := prefix + "-pipes"
			must("volume", "create", "--label", label, volume)
			network := prefix + "-net"
			must("network", "create", "--label", label, network)
			raw, client := identities(t)
			base := func(name, user, network string) []string {
				return []string{"create", "--name", name, "--label", label, "--network", network, "--ipc", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", user, "--cpus", "1", "--memory", "1g", "--memory-swap", "1g", "--pids-limit", "64", "--ulimit", "core=0:0", "--ulimit", "nofile=128:128", "--log-driver", "none", "--mount", "type=volume,src=" + volume + ",dst=/exchange,volume-nocopy"}
			}
			init := prefix + "-init"
			args := base(init, "0:0", "none")
			args = append(args, "--cap-add", "CHOWN", image, "--mode", "fifo-init")
			must(args...)
			containers = append(containers, init)
			must("start", init)
			if strings.TrimSpace(string(must("wait", init))) != "0" {
				t.Fatal("FIFO setup failed")
			}
			transport := prefix + "-transport"
			args = base(transport, "65532:65532", network)
			args = append(args, "--publish", "127.0.0.1::8443", "--env", "CSV_TLS_BOOTSTRAP", image, "--mode", "transport")
			cmd := exec.CommandContext(ctx, "docker", append([]string{"--host", host}, args...)...)
			cmd.Env = append(os.Environ(), "CSV_TLS_BOOTSTRAP="+string(raw))
			if _, e := cmd.Output(); e != nil {
				t.Fatal("transport create failed")
			}
			containers = append(containers, transport)
			must("start", transport)
			parser := prefix + "-parser"
			args = base(parser, "65533:65533", "container:"+transport)
			args = append(args, image, "--mode", "parser")
			must(args...)
			containers = append(containers, parser)
			must("start", parser)
			var mappings map[string][]struct{ HostIP, HostPort string }
			if json.Unmarshal(must("inspect", "--format", "{{json .NetworkSettings.Ports}}", transport), &mappings) != nil || len(mappings["8443/tcp"]) != 1 {
				t.Fatal("private port binding")
			}
			mapping := mappings["8443/tcp"][0]
			if mapping.HostIP != "127.0.0.1" {
				t.Fatal("nonlocal port")
			}
			var conn net.Conn
			var e error
			for {
				conn, e = (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(mapping.HostIP, mapping.HostPort))
				if e == nil {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("private listener unavailable")
				case <-time.After(20 * time.Millisecond):
				}
			}
			q, inputs := fixture(t, tc.op, tc.options, tc.files)
			var sink bytes.Buffer
			result, e := Exchange(ctx, tls.Client(conn, client), q, inputs, &sink)
			if e != nil || result.LogicalSHA256 != hash([]byte(tc.expected)) {
				t.Fatal("sandboxed private exchange failed", e)
			}
			for _, name := range []string{parser, transport} {
				if strings.TrimSpace(string(must("wait", name))) != "0" {
					t.Fatal("handler exit failed")
				}
			}
			// Assert the actual local profile, not just the generated definition.
			for _, name := range []string{parser, transport} {
				if strings.TrimSpace(string(must("inspect", "--format", "{{.HostConfig.ReadonlyRootfs}} {{.Config.User}} {{.HostConfig.PidMode}}", name))) != "true "+map[string]string{parser: "65533:65533", transport: "65532:65532"}[name] {
					t.Fatal("local runtime profile drift")
				}
			}
		})
	}
}
