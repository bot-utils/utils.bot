// Package paths defines the small, explicit public API and documentation surface.
package paths

// DocumentationRoutes lists the exact informational surface, without a
// wildcard or health endpoint. The edge currently restricts every route by IP.
var DocumentationRoutes = []string{"/", "/readme", "/docs", "/disclaimers", "/info", "/terms", "/agents", "/openapi", "/openapi/json", "/openapi.yaml", "/openapi.json", "/.well-known/security.txt", "/llms.txt", "/robots.txt", "/sitemap.xml", "/v1/pdf/text", "/assets/favicon.svg", "/assets/swagger-ui.css", "/assets/swagger-ui-bundle.js", "/assets/swagger-ui-bundle.js.LICENSE.txt", "/assets/initializer.js", "/assets/site.css", "/assets/site-v3.css", "/assets/site-v4.css", "/assets/site-v5.css", "/assets/initializer-v3.js", "/assets/initializer-v4.js", "/assets/SWAGGER-UI-LICENSE", "/assets/SWAGGER-UI-NOTICE"}

var Routes = append(append([]string(nil), DocumentationRoutes...), "/health")

func Supported(path string) bool {
	for _, allowed := range Routes {
		if path == allowed {
			return true
		}
	}
	return false
}
