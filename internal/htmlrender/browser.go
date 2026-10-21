package htmlrender

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"pdfservice/internal/browser"
	"pdfservice/internal/htmllimits"
)

const MaxBrowserSource = 16 << 20
const MaxBrowserResource = 4 << 20

// BrowserFetcher is experimental and is deliberately not selected by ordinary
// HTML deployments. A missing Chromium sandbox/network launcher fails closed.
type BrowserFetcher struct {
	Launcher, Executable string
	// Warm is captured customer-free; each cloned VM consumes its copy once.
	Warm *browser.Warm
	// Timing receives durations only, never request/source content.
	Timing func(startup, render time.Duration)
}

func (f BrowserFetcher) Fetch(ctx context.Context, raw string, domains DomainCheck) (Result, error) {
	transport := &http.Transport{Proxy: nil, DialContext: publicDial(net.DefaultResolver, &net.Dialer{Timeout: 3 * time.Second}), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10, DisableCompression: true, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	return f.fetch(ctx, raw, domains, transport)
}
func (f BrowserFetcher) fetch(ctx context.Context, raw string, domains DomainCheck, transport http.RoundTripper) (Result, error) {
	original, err := CanonicalURL(raw)
	if err != nil {
		return Result{}, err
	}
	if domains == nil {
		return Result{}, ErrThreats
	}
	if err := domains.Check(ctx, original.Hostname(), time.Now()); err != nil {
		return Result{}, err
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, htmllimits.HTMLFetchSeconds*time.Second)
	defer cancel()
	started := time.Now()
	var session *browser.Session
	if f.Warm != nil {
		session, err = f.Warm.Take(ctx)
		defer f.Warm.Close()
	} else {
		var dir string
		dir, err = os.MkdirTemp("", "utils-browser-")
		if err == nil {
			defer os.RemoveAll(dir) // This job's private ephemeral profile.
			session, err = browser.Start(ctx, f.Launcher, f.Executable, dir)
		}
	}
	if err != nil {
		return Result{}, err
	}
	defer session.Close()
	startup := time.Since(started)
	broker := &browserBroker{domains: domains, transport: transport}
	rendered, err := browser.Render(ctx, session, original.String(), broker.Fetch)
	if err != nil {
		if errors.Is(err, browser.ErrLimit) || errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
			return Result{}, ErrComplexity
		}
		return Result{}, err
	}
	final, err := CanonicalURL(rendered.URL)
	if err != nil {
		return Result{}, ErrBlocked
	}
	if err := domains.Check(ctx, final.Hostname(), time.Now()); err != nil {
		return Result{}, err
	}
	markdown, title, truncated, err := Convert(ctx, []byte(rendered.HTML), final)
	if err != nil {
		return Result{}, err
	}
	if f.Timing != nil {
		f.Timing(startup, time.Duration(rendered.RenderMS)*time.Millisecond)
	}
	if broker.status == 0 {
		return Result{}, ErrFetch
	}
	return Result{URL: original.String(), FinalURL: final.String(), SourceStatus: broker.status, SourceBytes: broker.documentBytes, JavaScript: true, Title: title, Markdown: markdown, Truncated: truncated}, nil
}

type browserBroker struct {
	domains                             DomainCheck
	transport                           http.RoundTripper
	total, count, status, documentBytes int
}

func (b *browserBroker) Fetch(ctx context.Context, r browser.Request) (browser.Response, error) {
	if r.Method != "GET" {
		return browser.Response{}, ErrBlocked
	}
	u, err := CanonicalURL(r.URL)
	if err != nil {
		return browser.Response{}, err
	}
	if b.domains == nil {
		return browser.Response{}, ErrThreats
	}
	if err := b.domains.Check(ctx, u.Hostname(), time.Now()); err != nil {
		return browser.Response{}, err
	}
	b.count++
	if b.count > browser.MaxRequests {
		return browser.Response{}, ErrComplexity
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return browser.Response{}, ErrURL
	}
	req.Header.Set("User-Agent", "utils.bot/1.0 (+https://utils.bot/info)")
	req.Header.Set("Accept-Encoding", "identity")
	// Never forward browser/caller headers, cookies, authorization or referrers.
	resp, err := b.transport.RoundTrip(req)
	if err != nil {
		if errors.Is(err, ErrBlocked) {
			return browser.Response{}, ErrBlocked
		}
		return browser.Response{}, ErrFetch
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 599 {
		return browser.Response{}, ErrFetch
	}
	if encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); encoding != "" && encoding != "identity" {
		return browser.Response{}, ErrType
	}
	// XML is outside this HTML renderer's contract. Refuse network XML before
	// Chromium sees it, including XHTML/SVG and XML returned to scripts. This
	// narrows native-parser exposure; JavaScript can still construct XML locally,
	// so this is not a claim that Expat or every XML path is unreachable.
	typ, params, typeErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if typ == "text/xml" || typ == "application/xml" || strings.HasSuffix(typ, "+xml") {
		return browser.Response{}, ErrType
	}
	if resp.ContentLength > MaxBrowserResource {
		return browser.Response{}, ErrSize
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBrowserResource+1))
	if err != nil {
		return browser.Response{}, ErrFetch
	}
	if len(body) > MaxBrowserResource || b.total+len(body) > MaxBrowserSource {
		return browser.Response{}, ErrSize
	}
	b.total += len(body)
	headers := map[string]string{}
	for _, name := range []string{"Content-Type", "Content-Security-Policy", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "X-Content-Type-Options"} {
		if value := resp.Header.Get(name); value != "" {
			headers[name] = value
		}
	}
	// Never let missing or weaker source headers enable script/style sniffing.
	headers["X-Content-Type-Options"] = "nosniff"
	// Redirects are returned to Chromium so each hop is independently intercepted,
	// validated, reputationally checked and fetched through the same pinned dialer.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location, err := u.Parse(resp.Header.Get("Location"))
		if err != nil || resp.Header.Get("Location") == "" {
			return browser.Response{}, ErrFetch
		}
		canonical, err := CanonicalURL(location.String())
		if err != nil {
			return browser.Response{}, err
		}
		if err := b.domains.Check(ctx, canonical.Hostname(), time.Now()); err != nil {
			return browser.Response{}, err
		}
		headers["Location"] = canonical.String()
	} else if r.Type == "Document" {
		charset := strings.ToLower(params["charset"])
		if typeErr != nil || typ != "text/html" || (charset != "" && charset != "utf-8" && charset != "us-ascii") || !utf8.Valid(body) {
			return browser.Response{}, ErrType
		}
		b.status = resp.StatusCode
		b.documentBytes = len(body)
	}
	return browser.Response{Status: resp.StatusCode, Headers: headers, Body: body}, nil
}
