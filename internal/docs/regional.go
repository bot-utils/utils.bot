package docs

import (
	"pdfservice/internal/protocol"
	"strings"
)

// Regional ingress changes routing, not the purchased processing or privacy
// contract. Keep machine-readable policy flags and links consistent with it.
func configureRegionalSpec(spec map[string]any) {
	policy := spec["x-service-policy"].(map[string]any)
	policy["edgeMissingPaymentQuote"] = false
	policy["pdfIngress"] = "regional HTTPS ALB/WAF; synchronous raw-PDF POST"
	for _, raw := range spec["x-service-policies"].([]any) {
		p := raw.(map[string]any)
		if p["title"] == "Routes and edge responses" {
			p["description"] = "Use POST https://api.utils.bot/v1/pdf/text. Unsupported API paths return 404 and unsupported methods on the PDF path return 405. OPTIONS is available only for the hosted Swagger UI browser preflight; it does not parse or charge. Query parameters and ranges are unsupported. The regional receiver returns a standard x402 quote before reading a body when PAYMENT-SIGNATURE is missing; a present signature still requires cryptographic verification before upload and parsing, then confirmed settlement before result delivery. Regional WAF applies geographic, header and rate controls. The website, documentation and legal pages stay at https://utils.bot. Legacy website PDF POSTs receive a fixed 307 redirect to the canonical API. Use the canonical API directly to avoid an extra redirect/upload."
		}
	}
	var links func(any)
	links = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			for key, child := range node {
				if key == "description" {
					if value, ok := child.(string); ok {
						node[key] = strings.ReplaceAll(value, "](/", "]("+protocol.SiteOrigin+"/")
					}
				}
				links(child)
			}
		case []any:
			for _, child := range node {
				links(child)
			}
		}
	}
	links(spec)
}
