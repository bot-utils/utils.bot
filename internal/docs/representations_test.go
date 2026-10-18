package docs

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocumentationNegotiation(t *testing.T) {
	h := New("https://example.test/v1/pdf/text")
	for _, tc := range []struct {
		accept, content string
		status          int
	}{
		{"", "text/html", 200}, {"*/*", "text/html", 200},
		{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html", 200},
		{"application/yaml", "application/yaml", 200}, {"application/vnd.oai.openapi+yaml", "application/yaml", 200},
		{"application/json", "application/json", 200},
		{"text/html;q=0.2,application/yaml;q=0.8", "application/yaml", 200},
		{"application/yaml;q=0,*/*;q=1", "application/json", 200},
		{"text/html;q=0,application/yaml;q=0,application/json;q=0", "text/plain", 406},
		{"application/xml", "text/plain", 406},
		{"application/yaml;q=NaN,text/html;q=0.2", "text/html", 200},
		{"application/yaml;q=2,text/html;q=0.2", "text/html", 200},
	} {
		t.Run(tc.accept, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept", tc.accept)
			r.Header.Set("User-Agent", "Mozilla/5.0 AgentBot")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || !strings.HasPrefix(w.Header().Get("Content-Type"), tc.content) || w.Header().Get("Vary") != "Accept" {
				t.Fatalf("wrong representation: status=%d headers=%v", w.Code, w.Header())
			}
		})
	}
}

func TestDocumentationTermsMatchAllRepresentations(t *testing.T) {
	h := New("https://example.test/v1/pdf/text")
	request := func(path, accept string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	j := request("/openapi/json", "text/html")
	var spec map[string]any
	if err := json.Unmarshal(j.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	y := request("/openapi", "text/html")
	root := request("/", "application/yaml")
	if y.Code != 200 || y.Header().Get("Content-Type") != "application/yaml" || !bytes.Equal(y.Body.Bytes(), root.Body.Bytes()) {
		t.Fatal("agent routes do not return canonical YAML")
	}
	want, err := jsonYAML(j.Body.Bytes())
	if err != nil || !bytes.Equal(want, y.Body.Bytes()) {
		t.Fatal("JSON/YAML canonical document mismatch")
	}
	policies := request("/info", "text/html")
	legal := request("/terms", "text/html")
	raw, _ := json.Marshal(spec["x-service-policies"])
	var terms []struct{ Title, Description string }
	if err := json.Unmarshal(raw, &terms); err != nil {
		t.Fatal(err)
	}
	if len(terms) != 16 {
		t.Fatal("policies lost during documentation split")
	}
	for _, term := range terms {
		quoted, _ := json.Marshal(term.Description)
		if !strings.Contains(y.Body.String(), string(quoted)[1:len(quoted)-1]) {
			t.Fatalf("policy absent from YAML: %s", term.Title)
		}
		if !informationSections[term.Title] && !termsSections[term.Title] {
			continue
		}
		for _, paragraph := range strings.Split(term.Description, "\n\n") {
			if !strings.Contains(html.UnescapeString(policies.Body.String()+legal.Body.String()), paragraph) {
				t.Fatalf("policy paragraph absent from Markdown: %s", term.Title)
			}
		}
	}
	description := spec["info"].(map[string]any)["description"].(string)
	if len(strings.Fields(description)) > 100 || strings.Contains(strings.ToLower(description), "prototype") {
		t.Fatal("description is too long or uses prototype language")
	}
	all := string(raw)
	for _, required := range []string{"Parsing failures are not charged", "100 MiB", "AI agents", "do not store", "open source", "all rights reserved", "untrusted data", "five minutes", "OCR is not included", "One request can be admitted at a time per task"} {
		if !strings.Contains(all, required) {
			t.Fatal("missing disclosure", required)
		}
	}
	swagger := request("/docs", "text/html")
	if strings.Contains(html.UnescapeString(swagger.Body.String()), description) {
		t.Fatal("Swagger description repeated in header")
	}
	if !strings.Contains(swagger.Body.String(), `id="swagger-ui"`) || !strings.Contains(swagger.Header().Get("Link"), "</openapi>") {
		t.Fatal("Swagger or extensionless discovery missing")
	}
	head := httptest.NewRecorder()
	h.ServeHTTP(head, httptest.NewRequest("HEAD", "/openapi", nil))
	if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Type") != "application/yaml" {
		t.Fatal("HEAD does not preserve YAML metadata")
	}
	for _, tc := range []struct{ old, target string }{{"/agents", "/openapi"}, {"/openapi.yaml", "/openapi"}, {"/openapi.json", "/openapi/json"}, {"/disclaimers", "/info"}} {
		for _, method := range []string{"GET", "HEAD"} {
			for _, accept := range []string{"text/html", "application/yaml", "application/json"} {
				r := httptest.NewRequest(method, tc.old, nil)
				r.Header.Set("Accept", accept)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 308 || w.Header().Get("Location") != tc.target {
					t.Fatal("legacy route must redirect to its fixed canonical URL", method, tc.old, accept)
				}
				if method == "HEAD" && w.Body.Len() != 0 {
					t.Fatal("redirect HEAD returned a body", tc.old)
				}
			}
		}
	}
}

func TestYAMLSerializationPreservesSpecialScalars(t *testing.T) {
	data := []byte(`{"200":"yes","empty":[],"mapping":{},"nested":[{"false":"a: b\n# ! & * \"quoted\"","n":9007199254740993}],"null":null}`)
	got, err := jsonYAML(data)
	want := `"200": "yes"
"empty": []
"mapping": {}
"nested":
  -
    "false": "a: b\n# ! \u0026 * \"quoted\""
    "n": 9007199254740993
"null": null
`
	if err != nil || string(got) != want {
		t.Fatalf("YAML scalar/type preservation: %s error=%v", got, err)
	}
	if _, err := jsonYAML([]byte(`{`)); err == nil {
		t.Fatal("invalid source JSON accepted")
	}
}
