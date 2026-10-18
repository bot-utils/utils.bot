package docs

import (
	"encoding/xml"
	"net/http/httptest"
	"pdfservice/internal/protocol"
	"pdfservice/internal/serviceinfo"
	"strings"
	"testing"
)

func TestDiscoveryAndLaunchCopyFollowExplicitAccessSetting(t *testing.T) {
	baseCfg, err := protocol.NewConfig(protocol.ModeBase, "0x2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"0", "1"} {
		cfg, err := baseCfg.WithPublicAccess(setting)
		if err != nil {
			t.Fatal(err)
		}
		h := NewWithConfig("https://utils.bot/v1/pdf/text", cfg)
		discovery := Discovery("https://utils.bot", cfg)
		for path, want := range discovery {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Accept", "text/html")
			r.Host = "spoofed.invalid"
			h.ServeHTTP(w, r)
			if w.Code != 200 || w.Body.String() != want.Body || w.Header().Get("Content-Type") != want.ContentType {
				t.Fatal("edge/origin discovery drift", path)
			}
			if cfg.PublicAccess() && w.Header().Get("X-Robots-Tag") != "" {
				t.Fatal("public discovery remains noindex")
			}
			if !cfg.PublicAccess() && w.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
				t.Fatal("private discovery indexing allowed")
			}
		}
		robots := discovery["/robots.txt"].Body
		if cfg.PublicAccess() {
			if !strings.Contains(robots, "Allow: /\n") || strings.Contains(robots, "Disallow: /\n") || !strings.Contains(robots, "Disallow: /health") {
				t.Fatal("wrong public crawl policy")
			}
		} else if !strings.Contains(robots, "Disallow: /\n") {
			t.Fatal("private site made crawlable")
		}
		llms := discovery["/llms.txt"].Body
		for _, notice := range []string{serviceinfo.Details().Summary, "/readme", "/openapi", "/terms", "/info", "100 MiB", "Successful partial or blank", "user's permission"} {
			if !strings.Contains(llms, notice) {
				t.Fatal("agent directory missing value or boundary", notice)
			}
		}
		var sitemap struct {
			URLs []struct {
				Location string `xml:"loc"`
			} `xml:"url"`
		}
		if err := xml.Unmarshal([]byte(discovery["/sitemap.xml"].Body), &sitemap); err != nil || len(sitemap.URLs) != 6 {
			t.Fatal("invalid canonical sitemap", err)
		}
		for _, path := range []string{"/", "/docs", "/openapi/json"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			body := w.Body.String()
			if path == "/" && (cfg.Requirements().Amount != "10000" || !strings.Contains(body, "PDF pricing: 0.01 USDC for PDFs through 25 MiB; 0.02 USDC above 25 MiB through 100 MiB") || !strings.Contains(body, "Successful partial or blank results are charged the full fee")) {
				t.Fatal("visible pricing diverges from quote or output policy")
			}
			if cfg.PublicAccess() && (strings.Contains(body, "Private testing") || strings.Contains(body, "Public API access has not opened yet") || strings.Contains(body, "PDF POST access is currently restricted") || strings.Contains(body, "Restricted cdp-base endpoint")) {
				t.Fatal("public copy still describes private site", path)
			}
			if !cfg.PublicAccess() && path == "/" && !strings.Contains(body, "Public API access has not opened yet") {
				t.Fatal("private status omitted")
			}
		}
	}
}
