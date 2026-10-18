package docs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"pdfservice/internal/protocol"
)

func TestVendoredSwaggerIntegrityAndSafeInitializer(t *testing.T) {
	raw, err := os.ReadFile("swagger-assets.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("invalid asset manifest")
	}
	for name, meta := range manifest.Files {
		data, err := files.ReadFile("assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != meta.SHA256 {
			t.Fatal("changed vendored asset", name)
		}
	}
	data, err := files.ReadFile("assets/initializer.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`url: "/openapi"`, "queryConfigEnabled: false", "validatorUrl: null", "persistAuthorization: false"} {
		if !strings.Contains(string(data), required) {
			t.Fatal("unsafe Swagger initializer", required)
		}
	}
}

func TestSpecificationAndReferences(t *testing.T) {
	h := New("https://example.test/v1/pdf/text")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/openapi/json", nil))
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if spec["openapi"] != "3.0.3" {
		t.Fatal("missing OpenAPI version")
	}
	server := spec["servers"].([]any)[0].(map[string]any)
	if server["url"] != "https://example.test" {
		t.Fatal("wrong canonical server")
	}
	paths := spec["paths"].(map[string]any)
	op := paths["/v1/pdf/text"].(map[string]any)["post"].(map[string]any)
	content := op["requestBody"].(map[string]any)["content"].(map[string]any)
	schema := content["application/pdf"].(map[string]any)["schema"].(map[string]any)
	if schema["maxLength"] != float64(protocol.MaxPDF) || schema["format"] != "binary" {
		t.Fatal("upload contract differs")
	}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok {
				var current any = spec
				if !strings.HasPrefix(ref, "#/") {
					t.Fatalf("external ref %s", ref)
				}
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					m, ok := current.(map[string]any)
					if !ok {
						t.Fatalf("unresolved ref %s", ref)
					}
					current, ok = m[part]
					if !ok {
						t.Fatalf("unresolved ref %s", ref)
					}
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(spec)
}

func TestDocsDoNotUseExternalScriptsOrRequestConfig(t *testing.T) {
	h := New("https://example.test/v1/pdf/text")
	for _, path := range []string{"/", "/docs", "/info"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path+"?url=https://untrusted.invalid/spec", nil)
		r.Header.Set("Accept", "text/html")
		h.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "utils.bot") {
			t.Fatalf("docs missing at %s", path)
		}
		if strings.Contains(w.Body.String(), "untrusted.invalid") || strings.Contains(w.Body.String(), `src="https://`) {
			t.Fatal("request-controlled or external script")
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
			t.Fatal("missing browser policy")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/anything", nil))
	if w.Code != 404 {
		t.Fatal("unknown path became a documentation page")
	}
}
