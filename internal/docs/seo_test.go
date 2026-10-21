package docs

import (
	"encoding/json"
	"encoding/xml"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"pdfservice/internal/paths"
)

func TestHomepageIsCrawlableHTMLWithoutSwaggerOrIdentityGuessing(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	var first string
	for _, ua := range []string{"Mozilla/5.0", "Googlebot", "OAI-SearchBot", "agent", ""} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Accept", "*/*")
		r.Host = "untrusted.invalid"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		body := w.Body.String()
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Fatal("crawler received something other than HTML", ua)
		}
		if first != "" && body != first {
			t.Fatal("user-agent cloaking or content drift")
		}
		first = body
		if strings.Contains(body, `src="/assets/swagger-ui`) || strings.Contains(body, `href="/assets/swagger-ui.css"`) || strings.Contains(body, "openapi.yaml") || strings.Contains(body, "untrusted.invalid") || len(body) > 20<<10 {
			t.Fatal("homepage bundles Swagger, advertises extension URL, trusts Host or is too large")
		}
		for _, required := range []string{`<title>Tools for AI agents | utils.bot</title>`, `<meta name="description"`, `<link rel="canonical" href="https://utils.bot/">`, `href="/openapi"`, `href="/docs"`, `href="/info"`, `<main id="main"`, `A toolbox for<br>AI agents.`, `PDF text extraction`, `href="/docs#/Tools/extractPDFText"`, `Private testing`} {
			if !strings.Contains(body, required) {
				t.Fatal("missing visible content/discovery/metadata", required)
			}
		}
		if strings.Count(body, "<h1 ") != 1 || strings.Contains(body, `src="https://`) {
			t.Fatal("missing single primary heading or added remote script")
		}
	}
	data := regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`).FindStringSubmatch(first)
	if len(data) != 2 {
		t.Fatal("missing structured site identity")
	}
	var structured map[string]any
	if err := json.Unmarshal([]byte(data[1]), &structured); err != nil {
		t.Fatal("invalid JSON-LD", err)
	}
	graph := structured["@graph"].([]any)
	if len(graph) != 2 || graph[0].(map[string]any)["name"] != "utils.bot" || graph[1].(map[string]any)["url"] != "https://utils.bot/" {
		t.Fatal("structured metadata does not match visible identity")
	}
}

func TestDiscoveryRoutesHaveFixedFormatsAndSitemapContainsRealPages(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, tc := range []struct{ path, want string }{{"/openapi", "application/yaml"}, {"/openapi/json", "application/json"}, {"/docs", "text/html"}, {"/info", "text/markdown"}, {"/readme", "text/markdown"}, {"/llms.txt", "text/plain"}} {
		for _, accept := range []string{"text/html", "application/json", "application/yaml"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", tc.path, nil)
			r.Header.Set("Accept", accept)
			h.ServeHTTP(w, r)
			if !paths.Supported(tc.path) || w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), tc.want) {
				t.Fatalf("cacheable route varied by Accept or missing at edge: %s %s", tc.path, accept)
			}
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/sitemap.xml", nil))
	var sitemap struct {
		URLs []struct {
			Location string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &sitemap); err != nil || len(sitemap.URLs) != 6 {
		t.Fatal("invalid sitemap", err)
	}
	for _, u := range sitemap.URLs {
		if !strings.HasPrefix(u.Location, "https://utils.bot/") || !paths.Supported(strings.TrimPrefix(u.Location, "https://utils.bot")) {
			t.Fatal("sitemap invents an unserved URL", u.Location)
		}
	}
}

func TestDocumentationDoesNotGenerateMultipartRanges(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, header := range []string{"Range", "If-Range"} {
		r := httptest.NewRequest("GET", "/assets/swagger-ui-bundle.js", nil)
		r.Header.Set(header, "bytes=0-0")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || w.Body.Len() > 128 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("range generated asset content")
		}
	}
}
