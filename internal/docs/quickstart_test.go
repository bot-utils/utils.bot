package docs

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"pdfservice/internal/protocol"
	"pdfservice/internal/serviceinfo"
	"strings"
	"testing"
)

func TestQuickstartIsDiscoverableAndExamplesAreUseful(t *testing.T) {
	cfg, err := protocol.NewConfig(protocol.ModeBase, "0x"+strings.Repeat("2", 40))
	if err != nil {
		t.Fatal(err)
	}
	h := NewWithHTML(protocol.APIOrigin+"/v1/pdf/text", cfg.WithHTMLJavaScript(true))
	read := func(path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		return w.Body.String()
	}
	for _, path := range []string{"/", "/docs", "/info", "/terms"} {
		if !strings.Contains(read(path), "/docs#quickstart") {
			t.Error("quickstart not discoverable", path)
		}
	}
	for _, path := range []string{"/llms.txt", "/openapi", "/openapi/json"} {
		if !strings.Contains(read(path), "first-paid-call") {
			t.Error("machine-readable quickstart not discoverable", path)
		}
	}
	page := read("/docs")
	for _, part := range []string{`id="quickstart"`, "USDC on Base", protocol.APIOrigin + "/v1/pdf/text", "PAYMENT-SIGNATURE", "PAYMENT-RESPONSE", "truncated", "Never send us your private key", "Runnable TypeScript client", serviceinfo.RepositoryURL + "#first-paid-call"} {
		if !strings.Contains(page, part) {
			t.Error("incomplete customer-facing HTML quickstart", part)
		}
	}
	var spec map[string]any
	if json.Unmarshal([]byte(read("/openapi/json")), &spec) != nil {
		t.Fatal("invalid specification")
	}
	if spec["x-quickstart"].(map[string]any)["network"] != "eip155:8453" {
		t.Fatal("quickstart network drift")
	}
	paths := spec["paths"].(map[string]any)
	for _, route := range []string{"/v1/pdf/text", protocol.HTMLPath} {
		op := paths[route].(map[string]any)["post"].(map[string]any)
		if !strings.Contains(op["description"].(string), "A wallet address alone is not payment") {
			t.Fatal("missing actionable flow", route)
		}
		example := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["example"].(map[string]any)
		if example["truncated"] != false {
			t.Fatal("example partial unexpectedly")
		}
		if route == protocol.HTMLPath {
			if !strings.Contains(example["markdown"].(string), "# Example Domain") || example["javascript"] != true {
				t.Fatal("not a useful rendered result")
			}
		} else {
			pages := example["pages"].([]any)
			if len(pages) != 1 || pages[0].(map[string]any)["text"] != "Hello, agent." {
				t.Fatal("not a useful PDF result")
			}
		}
	}
	if read("/readme") != serviceinfo.Markdown() {
		t.Fatal("served README drift")
	}
	repo, err := os.ReadFile("../../README.md")
	if err != nil || string(repo) != serviceinfo.Markdown() {
		t.Fatal("repository/website README mismatch", err)
	}
	for _, part := range []string{"@x402/fetch@2.28.0", "setSpendControls", "eip155:8453", "PAYMENT-SIGNATURE", "PAYMENT-RESPONSE", "identical input", "does not persist an authorization", "0.02 USDC"} {
		if !strings.Contains(serviceinfo.Markdown(), part) {
			t.Error("missing client requirement", part)
		}
	}
}
