package docs

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"pdfservice/internal/protocol"
)

func TestPricingDisclosuresAndMachineContract(t *testing.T) {
	cfg, _ := protocol.NewConfig(protocol.ModeBase, "0x"+strings.Repeat("2", 40))
	h := NewWithConfig("https://api.utils.bot/v1/pdf/text", cfg)
	for _, path := range []string{"/", "/docs", "/openapi", "/openapi/json", "/terms", "/info", "/llms.txt"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		for _, notice := range []string{"0.01 USDC", "25 MiB", "0.02 USDC", "100 MiB"} {
			if w.Code != 200 || !strings.Contains(w.Body.String(), notice) {
				t.Fatalf("missing %q in %s", notice, path)
			}
		}
		if path == "/openapi/json" {
			var spec map[string]any
			if json.Unmarshal(w.Body.Bytes(), &spec) != nil {
				t.Fatal("invalid spec")
			}
			tiers := spec["x-x402"].(map[string]any)["pricing"].([]any)
			if len(tiers) != 2 {
				t.Fatal("pricing tiers missing")
			}
			for i, raw := range tiers {
				tier := raw.(map[string]any)
				want := protocol.SmallAmount
				size := int64(1)
				maxBytes := protocol.SmallPDFLimit
				if i == 1 {
					want = protocol.LargeAmount
					size = protocol.SmallPDFLimit + 1
					maxBytes = protocol.MaxPDF
				}
				if tier["minBytes"] != float64(size) || tier["maxBytes"] != float64(maxBytes) || tier["requirements"].(map[string]any)["amount"] != want {
					t.Fatalf("wrong tier: %+v", tier)
				}
			}
			d := spec["paths"].(map[string]any)["/v1/pdf/text"].(map[string]any)["post"].(map[string]any)["description"].(string)
			for _, notice := range []string{"completed upload byte count", "partial result", "collect the full quoted fee", "three additional", "five minutes"} {
				if !strings.Contains(d, notice) {
					t.Fatal("missing route disclosure", notice)
				}
			}
		}
	}
}
