package docs

import (
	"net/http/httptest"
	"pdfservice/internal/paths"
	"pdfservice/internal/protocol"
	"strings"
	"testing"
)

func TestInformationIsCompleteMarkdownAndSeparateFromReadme(t *testing.T) {
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
		want := Information(cfg)
		if !strings.HasPrefix(want, "# utils.bot: information and privacy\n\n") || strings.Contains(want, `\n\n`) || strings.Contains(want, "/about") {
			t.Fatal("not canonical plain Markdown")
		}
		for _, section := range []string{"## Privacy", "## Limits and capacity", "## Retries and payment binding", "## Contact and requests", "## Data security and Illinois notices"} {
			if !strings.Contains(want, section) {
				t.Fatal("essential policy lost", section)
			}
		}
		if mode != protocol.ModeMock && strings.Contains(want, "MOCK PAYMENTS ONLY") {
			t.Fatal("mode mismatch")
		}
		for _, accept := range []string{"text/html", "application/json", "text/markdown", "*/*"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/info", nil)
			r.Header.Set("Accept", accept)
			r.Host = "untrusted.invalid"
			h.ServeHTTP(w, r)
			if w.Code != 200 || w.Body.String() != want || w.Header().Get("Content-Type") != "text/markdown; charset=utf-8" || strings.Contains(w.Body.String(), "untrusted.invalid") {
				t.Fatal("information varied with requester or lost policy")
			}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("HEAD", "/info", nil))
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("HEAD body")
		}
		if len(want) >= 9000 || !strings.Contains(want, "[service agreement](/terms)") {
			t.Fatal("information did not become a bounded document with a terms link")
		}
		legal := Terms(cfg)
		for _, section := range []string{"## Terms of use", "## Payments and remedies", "## Lawful use and complaints", "## Copyright"} {
			if !strings.Contains(legal, section) {
				t.Fatal("legal disclosure lost", section)
			}
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/terms", nil))
		if w.Code != 200 || w.Body.String() != legal || !strings.Contains(legal, "[privacy and processing rules](/info)") {
			t.Fatal("terms or privacy notice differs")
		}

	}
	if paths.Supported("/about") || !paths.Supported("/readme") || !paths.Supported("/info") {
		t.Fatal("active route rename incomplete")
	}
}
