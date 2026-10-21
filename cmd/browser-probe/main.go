// IAM-only synthetic Lambda experiment. Never accepts a customer URL or payment.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"pdfservice/internal/browser"
)

const launcher = "/opt/utils/browser-launch"
const executable = "/usr/lib/chromium/chromium-headless-shell"

type capability struct {
	Seccomp               bool   `json:"seccompInstalled"`
	IPv4Denied            bool   `json:"ipv4Denied"`
	IPv6Denied            bool   `json:"ipv6Denied"`
	UserNamespace         bool   `json:"userNamespace"`
	BrowserNamespaces     bool   `json:"browserNamespaces"`
	NamespaceErrno        int    `json:"namespaceErrno"`
	SetupStage            string `json:"setupStage"`
	SetupErrno            int    `json:"setupErrno"`
	ParentProtectionErrno int    `json:"parentProtectionErrno"`
	NoNewPrivilegesErrno  int    `json:"noNewPrivilegesErrno"`
	SeccompErrno          int    `json:"seccompErrno"`
}
type result struct {
	OK           bool       `json:"ok"`
	Code         string     `json:"code"`
	StartupMS    int64      `json:"startupMS"`
	RenderMS     int64      `json:"renderMS"`
	Capabilities capability `json:"capabilities"`
}

func probe(ctx context.Context, payload json.RawMessage) (out result, err error) {
	if !bytes.Equal(bytes.TrimSpace(payload), []byte("{}")) {
		out.Code = "invalid_probe_input"
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, launcher, "--probe")
	command.Env = []string{"LANG=C.UTF-8", "PATH=/usr/bin:/bin"}
	wire, _ := command.Output()
	if len(wire) < 2048 {
		_ = json.Unmarshal(wire, &out.Capabilities)
	}
	dir, e := os.MkdirTemp("", "utils-browser-probe-")
	if e != nil {
		out.Code = "profile_unavailable"
		return out, nil
	}
	defer os.RemoveAll(dir)
	started := time.Now()
	session, e := browser.Start(ctx, launcher, executable, dir)
	out.StartupMS = time.Since(started).Milliseconds()
	if e != nil {
		out.Code = "browser_unavailable"
		return out, nil
	}
	defer session.Close()
	rendered, e := browser.Render(ctx, session, "https://fixture.example/", func(_ context.Context, r browser.Request) (browser.Response, error) {
		if r.URL != "https://fixture.example/" || r.Method != "GET" {
			return browser.Response{}, errors.New("unexpected_probe_request")
		}
		return browser.Response{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: []byte(`<body><div id="a"></div><script>document.getElementById('a').textContent='browser-probe-rendered'</script>`)}, nil
	})
	out.RenderMS = rendered.RenderMS
	out.OK = e == nil && strings.Contains(rendered.HTML, "browser-probe-rendered") && out.Capabilities.Seccomp && out.Capabilities.IPv4Denied && out.Capabilities.IPv6Denied
	if out.OK {
		out.Code = "ok"
	} else {
		out.Code = "render_unavailable"
	}
	return out, nil
}
func main() { lambda.Start(probe) }
