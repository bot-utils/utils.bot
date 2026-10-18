// Package edge generates CloudFront's small JavaScript front door from the Go
// protocol definitions, so edge and backend payment requirements stay identical.
package edge

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"

	"pdfservice/internal/paths"
	"pdfservice/internal/protocol"
	"pdfservice/internal/serviceinfo"
)

//go:embed frontdoor.js
var source string

var Routes = paths.Routes

func Code(resource, ownerIP string) (string, error) {
	return CodeWithConfig(resource, ownerIP, protocol.Config{})
}
func CodeWithConfig(resource, ownerIP string, cfg protocol.Config) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme != "https" || (u.Host != "utils.bot" && u.Host != "api.utils.bot") || u.Path != "/v1/pdf/text" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.RawPath != "" || u.ForceQuery {
		return "", errors.New("edge resource must be the canonical utils.bot PDF endpoint")
	}
	ip := net.ParseIP(ownerIP)
	if ip == nil || ip.To4() == nil || strings.Contains(ownerIP, ":") {
		return "", errors.New("edge requires an owner IPv4 address")
	}
	quote := cfg.Quote(resource)
	body, err := json.Marshal(quote)
	if err != nil {
		return "", err
	}
	apiResource := ""
	if u.Host == "api.utils.bot" {
		apiResource = resource
		// Redirect legacy POSTs before their body can reach the origin. There
		// is no separate payment quote or payload forwarding at the CDN.
		body = nil
	}
	config, err := json.Marshal(struct {
		APIResource      string   `json:"apiResource,omitempty"`
		Public           bool     `json:"public"`
		ReadmeMarkdown   string   `json:"readmeMarkdown"`
		PaymentMode      string   `json:"paymentMode"`
		OwnerIP          string   `json:"ownerIP"`
		Routes           []string `json:"routes"`
		QuoteJSON        string   `json:"quoteJSON"`
		MaxPDF           int      `json:"maxPDF"`
		MaxPaymentHeader int      `json:"maxPaymentHeader"`
		LargeAmount      string   `json:"largeAmount"`
		SmallPDFLimit    int      `json:"smallPDFLimit"`
	}{apiResource, cfg.PublicAccess(), serviceinfo.Markdown(), cfg.Mode(), ownerIP, Routes, string(body), protocol.MaxPDF, protocol.MaxPaymentHeader, protocol.LargeAmount, protocol.SmallPDFLimit})
	if err != nil {
		return "", err
	}
	code := "var config = " + string(config) + ";\n" + source
	if len(code) > 10<<10 {
		return "", errors.New("edge function exceeds CloudFront code limit")
	}
	return code, nil
}
