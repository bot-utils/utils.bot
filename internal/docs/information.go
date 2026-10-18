package docs

import (
	"encoding/json"
	"fmt"
	"strings"

	"pdfservice/internal/protocol"
)

// baseSpec is the shared source for the API contract and complete information
// document. Payment mode changes cannot leave a stale mock-only policy online.
func baseSpec(cfg protocol.Config) map[string]any {
	raw, err := files.ReadFile("openapi.json")
	if err != nil {
		panic(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		panic(err)
	}
	configurePaymentSpec(spec, cfg)
	return spec
}

// The API specification retains every policy. These documents select the
// relevant sections without rewriting or weakening their operative text.
var informationSections = map[string]bool{
	"Purpose": true, "Limits and capacity": true, "Privacy": true,
	"Data security and Illinois notices": true, "Retries and payment binding": true,
	"Source and third-party licenses": true, "Contact and requests": true,
}
var termsSections = map[string]bool{
	"Terms of use": true, "Payments and remedies": true,
	"Lawful use and complaints": true, "Copyright": true,
}

func policyMarkdown(spec map[string]any, title, introduction string, selected map[string]bool) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# utils.bot: %s\n\n%s\n\n", title, introduction)
	for _, value := range spec["x-service-policies"].([]any) {
		policy := value.(map[string]any)
		if selected[policy["title"].(string)] {
			fmt.Fprintf(&out, "## %s\n\n%s\n\n", policy["title"], policy["description"])
		}
	}
	return out.String()
}

func informationMarkdown(spec map[string]any) string {
	return policyMarkdown(spec, "information and privacy", "Privacy, security, limits and retries. Read the [service agreement](/terms) and [API specification](/openapi) before paying. The toolbox introduction is at [/readme](/readme).", informationSections)
}
func termsMarkdown(spec map[string]any) string {
	return policyMarkdown(spec, "terms of service", "Read these terms, the [privacy and processing rules](/info), and the [API specification and payment quote](/openapi) before authorizing a paid request. Together they describe the purchased service.", termsSections)
}

func Information(cfg protocol.Config) string { return informationMarkdown(baseSpec(cfg)) }
func Terms(cfg protocol.Config) string       { return termsMarkdown(baseSpec(cfg)) }
