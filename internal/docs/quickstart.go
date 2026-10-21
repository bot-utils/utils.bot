package docs

import (
	"pdfservice/internal/protocol"
	"pdfservice/internal/serviceinfo"
)

const firstCall = "Use a standard x402 v2 client with an EOA wallet holding USDC on Base. Send the request → read the 402 quote → approve/sign the quoted payment → resend the identical body with PAYMENT-SIGNATURE → receive JSON and a PAYMENT-RESPONSE receipt. A wallet address alone is not payment. Read the terms, quote and limits before authorizing; successful partial and blank results are chargeable."

func configureQuickstart(spec map[string]any, base, apiBase string, cfg protocol.Config) {
	spec["info"].(map[string]any)["description"] = serviceinfo.Details().Summary + "\n\n" + serviceinfo.Details().Transparency + " [Inspect the source](" + serviceinfo.RepositoryURL + ").\n\nFirst paid call: " + "Send → read the 402 quote → sign → resend identical input → receive JSON. [Client quickstart and result](" + base + "/readme#first-paid-call)."
	spec["x-quickstart"] = map[string]any{"description": firstCall, "url": base + "/readme#first-paid-call", "apiOrigin": apiBase, "network": cfg.Network(), "x402Version": 2}
	paths := spec["paths"].(map[string]any)
	// The README is the same embedded source in GitHub, Markdown and Swagger.
	readme := paths["/readme"].(map[string]any)["get"].(map[string]any)
	readme["description"] = serviceinfo.Details().Description
	readme["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["text/markdown"].(map[string]any)["example"] = serviceinfo.Markdown()
	for _, route := range []string{"/v1/pdf/text", protocol.HTMLPath} {
		path, ok := paths[route].(map[string]any)
		if !ok {
			continue
		}
		op := path["post"].(map[string]any)
		op["description"] = op["description"].(string) + "\n\n**First call.** " + firstCall + " [Client quickstart](" + base + "/readme#first-paid-call)."
		media := op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
		if route == protocol.HTMLPath {
			media["example"] = map[string]any{"url": "https://example.com/", "finalURL": "https://example.com/", "sourceStatus": 200, "title": "Example Domain", "markdown": "# Example Domain\nThis domain is for use in documentation examples.", "truncated": false, "javascript": cfg.HTMLJavaScript(), "sourceBytes": 1256}
		} else {
			media["example"] = map[string]any{"pageCount": 1, "truncated": false, "pages": []any{map[string]any{"index": 0, "width": 612, "height": 792, "text": "Hello, agent.", "sha256": "f147584aaf1619220e65bb2479151a9cd3e9f60a61bb39f835a2e1511510124c"}}, "selectedEngine": "pdfium", "attempts": []any{map[string]any{"engine": "pdfium", "outcome": "success"}}, "bodySHA256": "24375e11a0c6211f7c032d87c574045093cc3cae049de2b275985529b3f0adcf", "paymentMode": cfg.Mode()}
		}
	}
}
