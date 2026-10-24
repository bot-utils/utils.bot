package csvcloud

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"pdfservice/internal/csvwire"
	"testing"
	"time"
)

func TestPrivateStreamLinuxSandbox(t *testing.T) {
	image := os.Getenv("CSV_PRIVATE_LOCAL_STREAM_IMAGE")
	if image == "" {
		t.Skip("explicit local Docker validation required")
	}
	if image != "utils-csv-private-worker:api-stream-preflight" {
		t.Fatal("unreviewed local image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	label := "utils.bot.csv.validation=" + ID()
	docker := func(args ...string) []byte {
		t.Helper()
		out, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if e != nil {
			t.Fatalf("local sandbox setup failed: %s", out)
		}
		return out
	}
	exchange := "csv-local-exchange-" + ID()[:16]
	spool := "csv-local-spool-" + ID()[:16]
	for _, volume := range []string{exchange, spool} {
		docker("volume", "create", "--label", label, volume)
	}
	defer func() {
		exec.Command("docker", "container", "prune", "--force", "--filter", "label="+label).Run()
		exec.Command("docker", "volume", "prune", "--force", "--all", "--filter", "label="+label).Run()
	}()
	mounts := []string{"--mount", "type=volume,source=" + exchange + ",target=/exchange", "--mount", "type=volume,source=" + spool + ",target=/spool"}
	init := []string{"run", "--label", label, "--network", "none", "--read-only", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "CHOWN"}
	init = append(init, mounts...)
	init = append(init, image, "--mode", "fifo-init-stream")
	docker(init...)
	f, e := privateSmallFixture("transform")
	if e != nil {
		t.Fatal(e)
	}
	f.Request.Version = 2
	var request bytes.Buffer
	if csvwire.WriteRequest(&request, f.Request, map[string]io.Reader{"file": bytes.NewReader(f.Inputs["file"])}) != nil {
		t.Fatal("wire request")
	}
	args := []string{"run", "-i", "--label", label, "--network", "none", "--read-only", "--user", "65533:65533", "--cap-drop", "ALL", "--memory", "768m", "--cpus", "1"}
	args = append(args, mounts...)
	args = append(args, image, "--mode", "sandbox-stream-stdio")
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = &request
	var output, diagnostic bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &diagnostic
	if e = cmd.Run(); e != nil {
		t.Fatal("streaming sandbox rejected", e, diagnostic.String())
	}
	var encoded bytes.Buffer
	m, e := csvwire.ReadStreamResult(&output, &encoded)
	if e != nil || m.LogicalSHA256 != f.logicalSHA() || m.LogicalBytes != f.logicalBytes() || int64(m.Rows) != f.Rows || csvwire.VerifyStreamResult(m, bytes.NewReader(encoded.Bytes())) != nil {
		t.Fatal("sandbox independent oracle", e)
	}
	t.Log("Streaming parser passed all kernel probes before input; exact gzip/CSV/hash oracle matched")
}
