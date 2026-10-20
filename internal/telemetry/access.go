package telemetry

import "pdfservice/internal/paths"

// AccessRoute provides a finite aggregation label. RequestURL separately
// preserves actual incoming paths for debugging, with bounded query redaction.
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
