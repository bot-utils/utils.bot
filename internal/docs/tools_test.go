package docs

import (
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"pdfservice/internal/payment"
)

func TestToolCatalogLinksToOperationsAndRequiresSpecificDescriptions(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	read := func(path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		return w.Body.String()
	}
	initializer := read("/assets/initializer-v4.js")
	if !strings.Contains(initializer, "deepLinking: true") || !strings.Contains(initializer, `docExpansion: "none"`) {
		t.Fatal("operation deep links cannot open a focused reference")
	}
	home, raw, yaml := read("/"), read("/openapi/json"), read("/openapi")
	var spec map[string]any
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatal(err)
	}
	if len(toolsFromSpec(spec)) != 1 {
		t.Fatal("infrastructure endpoints must not appear as tools")
	}
	// Every process route must document its actual behavior in the same contract
	// used by Swagger UI and agent YAML. Future tools inherit this requirement.
	for route, node := range spec["paths"].(map[string]any) {
		for method, value := range node.(map[string]any) {
			op, ok := value.(map[string]any)
			if !ok {
				continue
			}
			name, _ := op["x-tool-name"].(string)
			if method != "post" && name == "" {
				continue
			}
			if name == "" {
				t.Fatal("process route missing catalog metadata", route)
			}
			description, _ := op["description"].(string)
			for _, section := range []string{"**Process.**", "**Payment flow.**", "**Privacy.**", "**Security and limits.**"} {
				if !strings.Contains(description, section) {
					t.Fatal("route-specific disclosure missing", route, section)
				}
			}
			quoted, _ := json.Marshal(description)
			if !strings.Contains(yaml, string(quoted)[1:len(quoted)-1]) {
				t.Fatal("route description lost in agent YAML", route)
			}
			if strings.Contains(description, "PDFium") || strings.Contains(description, "Poppler") {
				t.Fatal("dependency details in route description")
			}
		}
	}
	for _, tool := range toolsFromSpec(spec) {
		if !strings.Contains(home, `href="`+tool.DocsURL+`"`) {
			t.Fatal("missing operation deep link", tool.DocsURL)
		}
	}
	if strings.Contains(raw, `"/openapi.yaml":`) {
		t.Fatal("spec advertises obsolete suffix route")
	}
	retention := spec["x-service-policy"].(map[string]any)["knownDocumentFailureTTLSeconds"].(float64)
	if retention != 864000 || retention != payment.DocumentFailureLifetime.Seconds() || payment.DocumentFailureLifetime != 240*time.Hour {
		t.Fatal("retention contract and implementation diverged")
	}
	policy := spec["x-service-policy"].(map[string]any)
	if policy["sameDocumentRetrySeconds"] != payment.RetryLifetime.Seconds() || policy["maxPaidRetries"] != float64(payment.MaxPaidRetries) || policy["retryCountsAdmittedAttempts"] != true {
		t.Fatal("paid retry implementation and contract diverged")
	}
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	result := schemas["ParseResult"].(map[string]any)
	partial := result["properties"].(map[string]any)["truncated"].(map[string]any)
	if !strings.Contains(partial["description"].(string), "partial result") || !strings.Contains(partial["description"].(string), "chargeable") {
		t.Fatal("partial-result metadata is not disclosed")
	}
	// The only script on the static homepage is inert crawler metadata.
	for _, script := range regexp.MustCompile(`(?s)<script\b[^>]*>.*?</script>`).FindAllString(home, -1) {
		if !strings.HasPrefix(script, `<script type="application/ld+json">`) {
			t.Fatal("executable script added to static homepage")
		}
	}
	if regexp.MustCompile(`(?i)<(button|input|select|form|iframe|details)\b|\son[a-z]+=`).MatchString(home) {
		t.Fatal("homepage gained an interactive control")
	}
}

func TestFutureToolComesFromSpecWithoutAddingInfrastructureEndpoints(t *testing.T) {
	spec := map[string]any{"paths": map[string]any{
		"/v1/future/process": map[string]any{"post": map[string]any{"operationId": "processFuture", "tags": []any{"Future"}, "x-tool-name": "Future process", "x-tool-summary": "A future operation."}},
		"/health":            map[string]any{"get": map[string]any{"operationId": "health"}},
	}}
	tools := toolsFromSpec(spec)
	if len(tools) != 1 || tools[0].DocsURL != "/docs#/Future/processFuture" || tools[0].Method != "POST" {
		t.Fatal(tools)
	}
}
