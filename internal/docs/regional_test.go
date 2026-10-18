package docs

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"pdfservice/internal/protocol"
)

func TestRegionalSpecSeparatesPaidAPIFromWebsiteAndLegalURLs(t *testing.T) {
	h := New(protocol.APIOrigin + "/v1/pdf/text")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/openapi/json", nil))
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if spec["servers"].([]any)[0].(map[string]any)["url"] != protocol.APIOrigin {
		t.Fatal("wrong paid API")
	}
	if spec["info"].(map[string]any)["termsOfService"] != protocol.SiteOrigin+"/terms" || spec["externalDocs"].(map[string]any)["url"] != protocol.SiteOrigin+"/docs" {
		t.Fatal("legal/docs moved to API")
	}
	if spec["x-service-policy"].(map[string]any)["edgeMissingPaymentQuote"] != false {
		t.Fatal("stale CDN quote promise")
	}
	for path, raw := range spec["paths"].(map[string]any) {
		item := raw.(map[string]any)
		if path == "/v1/pdf/text" {
			if item["servers"] != nil {
				t.Fatal("paid route overrides API")
			}
			continue
		}
		if item["servers"].([]any)[0].(map[string]any)["url"] != protocol.SiteOrigin {
			t.Fatal("website route points at API", path)
		}
	}
	for _, path := range []string{"/", "/docs", "/llms.txt", "/openapi"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Accept", "text/html")
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self' "+protocol.APIOrigin+";") {
			t.Fatal("Swagger cannot reach fixed API")
		}
		if path == "/llms.txt" && (!strings.Contains(w.Body.String(), protocol.APIOrigin+"/v1/pdf/text") || strings.Contains(w.Body.String(), protocol.APIOrigin+"/terms")) {
			t.Fatal("wrong discovery URLs", w.Body.String())
		}
		if path == "/" && !strings.Contains(w.Body.String(), `rel="canonical" href="https://utils.bot/"`) {
			t.Fatal("website canonical changed")
		}
	}
}
