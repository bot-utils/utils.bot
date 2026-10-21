package docs

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"pdfservice/internal/htmllimits"
	"pdfservice/internal/protocol"
)

func TestHTMLContractIsOptInAndEquivalentAcrossRepresentations(t *testing.T) {
	resource := protocol.APIOrigin + "/v1/pdf/text"
	normal := httptest.NewRecorder()
	NewWithConfig(resource, protocol.Config{}).ServeHTTP(normal, httptest.NewRequest("GET", "/openapi/json", nil))
	var original map[string]any
	json.Unmarshal(normal.Body.Bytes(), &original)
	if original["paths"].(map[string]any)[protocol.HTMLPath] != nil {
		t.Fatal("unreleased operation advertised by default")
	}
	h := NewWithHTML(resource, protocol.Config{})
	read := func(path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		return w.Body.String()
	}
	raw := read("/openapi/json")
	var spec map[string]any
	if json.Unmarshal([]byte(raw), &spec) != nil {
		t.Fatal("invalid spec")
	}
	operation := spec["paths"].(map[string]any)[protocol.HTMLPath].(map[string]any)["post"].(map[string]any)
	description := operation["description"].(string)
	limits := operation["x-limits"].(map[string]any)
	for key, want := range map[string]int{"requestJSONBytes": protocol.MaxHTMLRequest, "normalizedURLBytes": protocol.MaxHTMLURL, "hostnameLabels": protocol.MaxHTMLHostLabels, "redirects": protocol.MaxHTMLRedirects, "sourceHTMLBytes": protocol.MaxHTMLSource, "markdownUTF8Bytes": protocol.MaxMarkdown, "resultJSONBytes": protocol.MaxHTMLResult, "compressedBodyBytes": htmllimits.MaxCompressedBody, "albEnvelopeBytes": htmllimits.ALBMaxResponse, "htmlTokens": protocol.MaxHTMLTokens, "singleHTMLTokenBytes": protocol.MaxHTMLToken, "titleUTF8Bytes": protocol.MaxHTMLTitle, "fetchSeconds": protocol.HTMLFetchSeconds, "workerBudgetSeconds": protocol.HTMLWorkerSeconds, "requestBudgetSeconds": protocol.HTMLRequestSeconds} {
		if limits[key] != float64(want) {
			t.Error("bound drift", key, limits[key], want)
		}
	}
	for _, status := range []string{"406", "422"} {
		if !strings.Contains(operation["responses"].(map[string]any)[status].(map[string]any)["description"].(string), "uncharged") {
			t.Error("transport error charging policy missing", status)
		}
	}
	quote := protocol.Config{}.ForHTML().Quote(protocol.APIOrigin + protocol.HTMLPath)
	if !strings.Contains(quote.Resource.Description, "up to 4 MiB uncompressed result JSON") || !strings.Contains(quote.Resource.Description, "Accept-Encoding: gzip") || strings.Contains(quote.Resource.Description, "128 KiB") {
		t.Fatal("prepayment notice has stale output limits")
	}
	for _, s := range []string{"8,192-byte", "10 DNS labels", "200,000 tokens", "256 KiB", "1 KiB", "20-second", "65 seconds"} {
		if !strings.Contains(description, s) {
			t.Error("bounds missing from customer description", s)
		}
	}

	yaml := read("/openapi")
	for _, expected := range []string{"HaGeZi", "CERT Polska", "no JavaScript", "0.01 USDC", "4 MiB total uncompressed result JSON", "Accept-Encoding: gzip", "gzip_required", "response_size_limit", "truncated: true", "not stored or logged", "three additional", "five minutes", "prompt injection"} {
		if !strings.Contains(strings.ToLower(description), strings.ToLower(expected)) || !strings.Contains(strings.ToLower(yaml), strings.ToLower(expected)) {
			t.Error("missing shared contract", expected)
		}
	}
	if !strings.Contains(read("/"), "/docs#/Tools/htmlToMarkdown") {
		t.Fatal("catalog cannot deep-link operation")
	}
	if !strings.Contains(read("/llms.txt"), protocol.HTMLPath) || !strings.Contains(read("/info"), "URL-to-Markdown") {
		t.Fatal("agent/privacy material not updated")
	}
	// A regional API tool must not accidentally inherit the website-only server.
	path := spec["paths"].(map[string]any)[protocol.HTMLPath].(map[string]any)
	if path["servers"] != nil {
		t.Fatal("HTML routed to website", path["servers"])
	}
}

func TestJavaScriptContractDisclosesResourceAndRenderLimits(t *testing.T) {
	w := httptest.NewRecorder()
	NewWithHTML(protocol.APIOrigin+"/v1/pdf/text", protocol.Config{}.WithHTMLJavaScript(true)).ServeHTTP(w, httptest.NewRequest("GET", "/openapi/json", nil))
	var spec map[string]any
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
		t.Fatal("invalid spec")
	}
	op := spec["paths"].(map[string]any)[protocol.HTMLPath].(map[string]any)["post"].(map[string]any)
	description := op["description"].(string)
	for _, term := range []string{"sandboxed headless browser", "48 intercepted requests", "16 MiB aggregate", "4 MiB serialized DOM", "one additional second (1,000 ms)", "not a one-second total rendering limit", "There is no universal render-complete signal", "POST requests are unsupported", "cannot create Internet sockets", "no AWS/payment credentials", "Security refusals and fetch/conversion failures are uncharged", "main document must be text/html", "XML media types, including XHTML and SVG, are refused", "MIME sniffing is disabled"} {
		if !strings.Contains(description, term) {
			t.Error("missing browser contract", term)
		}
	}
	if strings.Contains(description, "No JavaScript execution") {
		t.Fatal("contradictory description")
	}
	props := spec["components"].(map[string]any)["schemas"].(map[string]any)["HTMLResult"].(map[string]any)["properties"].(map[string]any)
	if props["javascript"].(map[string]any)["enum"].([]any)[0] != true {
		t.Fatal("browser flag wrong")
	}
	limits := op["x-limits"].(map[string]any)
	if limits["browserRequests"] != float64(48) || limits["aggregateSourceBytes"] != float64(16<<20) || limits["javascriptSettleMilliseconds"] != float64(1000) {
		t.Fatal(limits)
	}
}

func TestJavaScriptRenderTimingPolicyMatchesYAMLAndJSON(t *testing.T) {
	h := NewWithHTML(protocol.APIOrigin+"/v1/pdf/text", protocol.Config{}.WithHTMLJavaScript(true))
	read := func(path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		return w.Body.String()
	}
	var spec map[string]any
	if json.Unmarshal([]byte(read("/openapi/json")), &spec) != nil {
		t.Fatal("invalid spec")
	}
	op := spec["paths"].(map[string]any)[protocol.HTMLPath].(map[string]any)["post"].(map[string]any)
	policy := op["x-render-policy"].(map[string]any)
	if policy["startSignal"] != "load" || policy["postLoadWaitMilliseconds"] != float64(1000) || policy["totalFetchRenderBudgetSeconds"] != float64(protocol.HTMLFetchSeconds) || policy["waitForNetworkIdle"] != false || policy["completeDynamicContentGuaranteed"] != false {
		t.Fatal("timing policy drift", policy)
	}
	yaml := read("/openapi")
	for _, term := range []string{"one additional second (1,000 ms)", "not a one-second total rendering limit", "no universal render-complete signal", "Late, lazy-loaded or interaction-dependent content may be absent", "x-render-policy", `"postLoadWaitMilliseconds": 1000`} {
		if !strings.Contains(yaml, term) {
			t.Error("timing missing from YAML", term)
		}
	}
}

func TestAgentDiscoveryUsesActualJavaScriptContract(t *testing.T) {
	w := httptest.NewRecorder()
	NewWithHTML(protocol.APIOrigin+"/v1/pdf/text", protocol.Config{}.WithHTMLJavaScript(true)).ServeHTTP(w, httptest.NewRequest("GET", "/llms.txt", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "bounded JavaScript rendering") || strings.Contains(w.Body.String(), "no JavaScript or uploaded HTML") {
		t.Fatal("agent discovery disagrees with renderer", w.Code)
	}
}
