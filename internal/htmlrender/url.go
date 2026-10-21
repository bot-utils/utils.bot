// Package htmlrender implements the URL-only HTML-to-Markdown operation.
package htmlrender

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"unicode"

	"pdfservice/internal/htmllimits"
)

const Path = htmllimits.HTMLPath
const MaxRequest = htmllimits.MaxHTMLRequest
const MaxHTML = htmllimits.MaxHTMLSource
const MaxMarkdown = htmllimits.MaxMarkdown
const MaxResult = htmllimits.MaxHTMLResult // Private worker result; public transport is checked separately.

var ErrURL = errors.New("url_not_supported")
var ErrBlocked = errors.New("destination_blocked")
var ErrThreats = errors.New("threat_data_unavailable")
var ErrFetch = errors.New("fetch_failed")
var ErrSize = errors.New("html_size_limit")
var ErrType = errors.New("html_required")
var ErrComplexity = errors.New("html_complexity_limit")

// CanonicalURL deliberately accepts only ASCII/punycode DNS hosts over HTTPS
// on port 443. Credentials, IP literals, local names and ambiguous URLs are out.
func CanonicalURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > htmllimits.MaxHTMLURL || strings.Contains(raw, "\\") || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return nil, ErrURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.ForceQuery {
		return nil, ErrURL
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, ErrURL
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !domainName(host) || strings.Count(host, ".")+1 > htmllimits.MaxHTMLHostLabels || net.ParseIP(host) != nil || strings.Contains(u.Host, "%") || (u.Port() != "" && u.Port() != "443") {
		return nil, ErrURL
	}
	// Numeric hosts may be interpreted as legacy IPv4 by other implementations.
	if strings.Trim(host, "0123456789.") == "" {
		return nil, ErrURL
	}
	for _, suffix := range []string{"localhost", "local", "internal", "home", "onion", "test", "invalid", "arpa", "amazonaws.com", "amazonaws.com.cn"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return nil, ErrBlocked
		}
	}
	u.Host = host
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	if len(u.String()) > htmllimits.MaxHTMLURL {
		return nil, ErrURL
	}
	return u, nil
}

func domainName(s string) bool {
	if len(s) < 3 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

var special = func() []netip.Prefix {
	// Conservative special-use exclusions, including translation/tunneling ranges.
	ranges := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"}
	out := make([]netip.Prefix, len(ranges))
	for i, r := range ranges {
		out[i] = netip.MustParsePrefix(r)
	}
	return out
}()

func publicAddress(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsPrivate() || (a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a)) {
		return false
	}
	for _, p := range special {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Validate ALL answers, then connect to a validated literal. There is no second
// DNS resolution between checking a name and opening its connection.
func publicDial(r resolver, d dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" || !domainName(host) {
			return nil, ErrBlocked
		}
		ips, err := r.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 || len(ips) > 32 {
			return nil, ErrBlocked
		}
		for _, ip := range ips {
			if !publicAddress(ip) {
				return nil, ErrBlocked
			}
		}
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, ErrFetch
	}
}
