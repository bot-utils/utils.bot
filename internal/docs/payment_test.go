package docs

import (
	"encoding/json"
	"net/http/httptest"
	"pdfservice/internal/protocol"
	"strings"
	"testing"
)

func TestRealPaymentDescriptionsAndSpecAreConsistent(t *testing.T) {
	for _, mode := range []string{protocol.ModeBase, protocol.ModeSepolia} {
		cfg, err := protocol.NewConfig(mode, "0x2222222222222222222222222222222222222222")
		if err != nil {
			t.Fatal(err)
		}
		h := NewWithConfig("https://utils.bot/v1/pdf/text", cfg)
		for _, path := range []string{"/", "/docs", "/info", "/llms.txt", "/openapi", "/openapi/json"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Accept", "text/html")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("%s status=%d", path, w.Code)
			}
			body := w.Body.String()
			if strings.Contains(body, "MOCK PAYMENTS ONLY") || strings.Contains(body, "payments are mocked") || strings.Contains(body, "mock payments ·") || strings.Contains(body, "Real payment acceptance is not yet available") {
				t.Fatalf("stale mock claim in %s", path)
			}
			if path == "/openapi/json" {
				var spec map[string]any
				if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
					t.Fatal("bad spec")
				}
				pay := spec["x-x402"].(map[string]any)
				if pay["requirements"].(map[string]any)["extra"].(map[string]any)["paymentFlow"] != "authorization" {
					t.Fatal("spec advertises wrong payment order")
				}
				if pay["mode"] != mode || pay["requirements"].(map[string]any)["network"] != cfg.Network() {
					t.Fatal("wrong spec payment configuration")
				}
				if strings.Contains(body, `"enum": [
                    "mock"`) {
					t.Fatal("stale mode enum")
				}
			}
		}
	}
}
