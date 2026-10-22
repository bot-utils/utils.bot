package flow

import (
	"os"
	"testing"
)

func TestDockerEndToEndFlow(t *testing.T) {
	if os.Getenv("CSV_DOCKER_TESTS") != "1" {
		t.Skip("requires explicitly enabled local Docker integration")
	}
	for _, op := range []string{"dedupe", "join", "aggregate", "transform"} {
		t.Run(op, func(t *testing.T) { runHTTPFlow(t, op, true) })
	}
}
