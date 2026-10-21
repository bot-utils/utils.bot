package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalDockerEndpointRejectsRemoteAndAmbiguousContexts(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"unix:///var/run/docker.sock", "unix://" + filepath.Join(home, ".docker", "run", "docker.sock"), "unix://" + filepath.Join(home, ".colima", "default", "docker.sock")} {
		raw, _ := json.Marshal([]any{map[string]any{"Endpoints": map[string]any{"docker": map[string]string{"Host": endpoint}}}})
		if got, err := localDockerEndpoint(raw); err != nil || got != endpoint {
			t.Fatal("supported local endpoint rejected", endpoint, err)
		}
	}
	for _, endpoint := range []string{"tcp://127.0.0.1:2375", "tcp://remote.example:2376", "ssh://remote.example", "unix://remote.example/var/run/docker.sock", "unix:///tmp/forwarded.sock", "unix:///var/run/docker.sock?remote=1", "unix:///var/run/docker.sock#remote", "", "npipe:////./pipe/docker_engine"} {
		raw, _ := json.Marshal([]any{map[string]any{"Endpoints": map[string]any{"docker": map[string]string{"Host": endpoint}}}})
		if _, err := localDockerEndpoint(raw); err == nil {
			t.Fatal("unsupported endpoint accepted", endpoint)
		}
	}
	for _, raw := range []string{"[]", "[{},{}]", "{}", "not json"} {
		if _, err := localDockerEndpoint([]byte(raw)); err == nil {
			t.Fatal("ambiguous context accepted", raw)
		}
	}
}

func TestLocalDockerRejectsOverridesBeforeInvokingCLI(t *testing.T) {
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "remote.example")
			t.Setenv("PATH", "/nonexistent")
			if _, err := localDocker(context.Background()); err == nil || err.Error() != "Docker endpoint overrides are not supported" {
				t.Fatal("override was not rejected before CLI execution", err)
			}
		})
	}
}

func TestLocalDockerCommandsPinEndpointAndRemoveAmbientOverrides(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://remote.example:2375")
	t.Setenv("DOCKER_CONTEXT", "remote")
	client := localDockerClient{endpoint: "unix:///var/run/docker.sock"}
	for _, args := range [][]string{{"create", "image"}, {"start", "--attach", "job"}, {"kill", "job"}, {"container", "prune"}, {"inspect", "job"}} {
		cmd := client.command(context.Background(), args...)
		if len(cmd.Args) < 4 || cmd.Args[1] != "--host" || cmd.Args[2] != client.endpoint || cmd.Args[3] != args[0] {
			t.Fatal("job command did not pin verified endpoint", cmd.Args)
		}
		for _, entry := range cmd.Env {
			if strings.HasPrefix(entry, "DOCKER_HOST=") || strings.HasPrefix(entry, "DOCKER_CONTEXT=") {
				t.Fatal("ambient Docker endpoint override inherited")
			}
		}
	}
}
