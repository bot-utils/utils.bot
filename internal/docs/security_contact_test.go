package docs

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdfservice/internal/paths"
	"pdfservice/internal/protocol"
)

func TestSecurityContactIsCurrentStaticAndDoesNotReflectRequest(t *testing.T) {
	const path = "/.well-known/security.txt"
	if !paths.Supported(path) {
		t.Fatal("security contact blocked by route admission")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", path, nil)
	r.Host = "attacker.invalid"
	r.Header.Set("Accept", "text/html")
	New("https://utils.bot/v1/pdf/text").ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || strings.Contains(body, "attacker.invalid") {
		t.Fatal("unsafe security contact representation")
	}
	if body != Discovery("https://utils.bot", protocol.Config{})[path].Body {
		t.Fatal("origin and edge contact differ")
	}
	for _, required := range []string{"Contact: mailto:info@utils.bot\n", "Canonical: https://utils.bot/.well-known/security.txt\n", "Preferred-Languages: en\n", "do not send documents or credentials"} {
		if !strings.Contains(body, required) {
			t.Fatal("missing security contact information", required)
		}
	}
	if strings.Count(body, "Expires: ") != 1 {
		t.Fatal("contact expiry must appear exactly once")
	}
	for _, line := range strings.Split(body, "\n") {
		if value, ok := strings.CutPrefix(line, "Expires: "); ok {
			expires, err := time.Parse(time.RFC3339, value)
			if err != nil || !expires.After(time.Now()) || time.Until(expires) > 365*24*time.Hour {
				t.Fatal("security contact expiry needs review", value, err)
			}
		}
	}
}
