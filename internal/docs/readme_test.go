package docs

import (
	"encoding/json"
	"html"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"pdfservice/internal/protocol"
	"pdfservice/internal/serviceinfo"
)

func TestAboutPromiseMatchesAgentContractAndHomepage(t *testing.T) {
	about := serviceinfo.Details()
	for _, mode := range []string{protocol.ModeMock, protocol.ModeSepolia, protocol.ModeBase} {
		payTo := "0x2222222222222222222222222222222222222222"
		if mode == protocol.ModeMock {
			payTo = ""
		}
		cfg, err := protocol.NewConfig(mode, payTo)
		if err != nil {
			t.Fatal(err)
		}
		h := NewWithConfig("https://utils.bot/v1/pdf/text", cfg)
		get := func(path string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Accept", "text/html")
			r.Header.Set("User-Agent", "arbitrary agent")
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("%s %s: %d", mode, path, w.Code)
			}
			return w
		}
		w := get("/readme")
		if w.Body.String() != serviceinfo.Markdown() || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/markdown") || w.Header().Get("Payment-Required") != "" {
			t.Fatal("about must be static free Markdown")
		}
		var spec map[string]any
		if err := json.Unmarshal(get("/openapi/json").Body.Bytes(), &spec); err != nil {
			t.Fatal(err)
		}
		if spec["info"].(map[string]any)["description"] != about.Summary {
			t.Fatal("pitch drift")
		}
		op := spec["paths"].(map[string]any)["/readme"].(map[string]any)["get"].(map[string]any)
		if op["description"] != about.Description || len(op["security"].([]any)) != 0 {
			t.Fatal("about description or free access drift")
		}
		example := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["text/markdown"].(map[string]any)["example"]
		if example != serviceinfo.Markdown() {
			t.Fatal("Swagger Markdown response example drift")
		}
		quoted, _ := json.Marshal(about.Description)
		if !strings.Contains(get("/openapi").Body.String(), string(quoted)[1:len(quoted)-1]) {
			t.Fatal("agent YAML lost promise")
		}
		home := get("/").Body.String()
		match := regexp.MustCompile(`<meta name="agent-message" content="([^"]*)">`).FindStringSubmatch(home)
		if len(match) != 2 || html.UnescapeString(match[1]) != about.Message || !strings.Contains(home, `href="/readme"`) || !strings.Contains(home, `href="mailto:info@utils.bot"`) {
			t.Fatal("crawler message or visible invitation missing")
		}
		head := httptest.NewRecorder()
		h.ServeHTTP(head, httptest.NewRequest("HEAD", "/readme", nil))
		if head.Code != 200 || head.Body.Len() != 0 {
			t.Fatal("HEAD body emitted")
		}
		if strings.Contains(get("/info").Body.String(), "Email is not configured yet") {
			t.Fatal("obsolete contact disclaimer")
		}
	}
	for _, notice := range []string{"30 days", "10 days", "seven days", "asynchronous", "public blockchain", "partial", "permission"} {
		if !strings.Contains(about.Description+about.Message, notice) {
			t.Fatal("missing necessary disclosure", notice)
		}
	}
}
