package server

import (
	"net/http"
	"strings"

	"pdfservice/internal/protocol"
)

// regionalCORS permits the hosted Swagger UI without changing server-to-server
// access. CORS is not authentication: payment and the private perimeter remain.
func (s *Server) regionalCORS(w http.ResponseWriter, r *http.Request) bool {
	if s.Resource != protocol.APIOrigin+"/v1/pdf/text" || r.URL.Path != "/v1/pdf/text" {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 && r.Method != http.MethodOptions {
		return false
	}
	if len(origins) != 1 || origins[0] != protocol.SiteOrigin {
		w.Header().Set("Connection", "close")
		write(w, 403, map[string]string{"error": "browser_origin_not_allowed"})
		return true
	}
	w.Header().Set("Access-Control-Allow-Origin", protocol.SiteOrigin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Expose-Headers", "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Request-ID, X-Payment-Mode, Retry-After, Link")
	if r.Method != http.MethodOptions {
		return false
	}
	if len(r.Header.Values("Access-Control-Request-Method")) != 1 || r.Header.Get("Access-Control-Request-Method") != "POST" || len(r.Header.Values("Access-Control-Request-Headers")) > 1 || len(r.Header.Get("Access-Control-Request-Headers")) > 256 || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		w.Header().Set("Connection", "close")
		write(w, 400, map[string]string{"error": "invalid_preflight"})
		return true
	}
	for _, header := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		switch strings.ToLower(strings.TrimSpace(header)) {
		case "", "content-type", "payment-signature":
		default:
			write(w, 400, map[string]string{"error": "unsupported_preflight_header"})
			return true
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, PAYMENT-SIGNATURE")
	w.Header().Set("Access-Control-Max-Age", "300")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return true
}
