package edge

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net"
	"pdfservice/internal/docs"
	"pdfservice/internal/protocol"
	"strings"
)

//go:embed static-document.js
var staticSource string

// StaticCode generates a bounded static document with the same private viewer
// and method/query/range gates as the main front door. It never reaches an origin.
func StaticCode(route, ownerIP string, cfg protocol.Config) (string, error) {
	return StaticCodeForResource(route, ownerIP, cfg, protocol.SiteOrigin+"/v1/pdf/text")
}

func StaticCodeForResource(route, ownerIP string, cfg protocol.Config, resource string) (string, error) {
	ip := net.ParseIP(ownerIP)
	if ip == nil || ip.To4() == nil || strings.Contains(ownerIP, ":") {
		return "", errors.New("static document requires owner IPv4")
	}
	var body string
	var documents map[string]docs.Document
	switch route {
	case "/info":
		body = docs.Information(cfg)
	case "/terms":
		body = docs.Terms(cfg)
	case "/discovery":
		documents = docs.DiscoveryForResource(resource, cfg)
	default:
		return "", errors.New("unsupported static document")
	}
	config, err := json.Marshal(struct {
		Public    bool                     `json:"public"`
		Documents map[string]docs.Document `json:"documents,omitempty"`
		OwnerIP   string                   `json:"ownerIP"`
		Route     string                   `json:"route"`
		Body      string                   `json:"body"`
	}{cfg.PublicAccess(), documents, ownerIP, route, body})
	if err != nil {
		return "", err
	}
	code := "var config=" + string(config) + ";\n" + staticSource
	if len(code) > 10<<10 {
		return "", errors.New("static document exceeds CloudFront code limit")
	}
	return code, nil
}
