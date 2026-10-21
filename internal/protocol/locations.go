package protocol

import "strings"

const (
	SiteOrigin = "https://utils.bot"
	APIOrigin  = "https://api.utils.bot"
)

// WebsiteBase keeps legal and discovery links on the website when the paid
// operation uses regional ingress. Other URLs retain local/mock behavior.
func WebsiteBase(resource string) string {
	base := strings.TrimSuffix(strings.TrimSuffix(resource, "/v1/pdf/text"), "/v1/html/markdown")
	if base == APIOrigin {
		return SiteOrigin
	}
	return base
}
