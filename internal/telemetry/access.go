package telemetry

import "pdfservice/internal/paths"

// AccessRoute returns only literals from our public route catalog. Never log
// arbitrary paths, queries, hostnames or submitted URLs: those can contain data.
func AccessRoute(path string) string {
	for _, known := range paths.Routes {
		if path == known {
			return known
		}
	}
	return "unsupported"
}
func AccessMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT":
		return method
	}
	return "OTHER"
}
