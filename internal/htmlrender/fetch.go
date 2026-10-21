package htmlrender

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"pdfservice/internal/htmllimits"
)

type DomainCheck interface {
	Check(context.Context, string, time.Time) error
}

type Result struct {
	URL          string `json:"url"`
	FinalURL     string `json:"finalURL"`
	SourceStatus int    `json:"sourceStatus"`
	Title        string `json:"title"`
	Markdown     string `json:"markdown"`
	Truncated    bool   `json:"truncated"`
	JavaScript   bool   `json:"javascript"`
	SourceBytes  int    `json:"sourceBytes"`
	Error        string `json:"error,omitempty"`
}

type Fetcher struct{ Domains DomainCheck }

func (f Fetcher) Fetch(ctx context.Context, raw string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, htmllimits.HTMLFetchSeconds*time.Second)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil, DialContext: publicDial(net.DefaultResolver, &net.Dialer{Timeout: 3 * time.Second}),
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10,
		DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	return fetch(ctx, raw, f.Domains, transport)
}

func fetch(ctx context.Context, raw string, domains DomainCheck, transport http.RoundTripper) (Result, error) {
	original, err := CanonicalURL(raw)
	if err != nil {
		return Result{}, err
	}
	check := func(u *url.URL) error {
		canonical, err := CanonicalURL(u.String())
		if err != nil {
			return err
		}
		if domains == nil {
			return ErrThreats
		}
		*u = *canonical
		return domains.Check(ctx, canonical.Hostname(), time.Now())
	}
	if err := check(original); err != nil {
		return Result{}, err
	}
	client := &http.Client{Transport: transport, Timeout: htmllimits.HTMLFetchSeconds * time.Second, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) > htmllimits.MaxHTMLRedirects {
			return ErrFetch
		}
		// Never disclose even the source URL to redirect destinations.
		next.Header.Del("Referer")
		return check(next.URL)
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, original.String(), nil)
	if err != nil {
		return Result{}, ErrURL
	}
	req.Header.Set("User-Agent", "utils.bot/1.0 (+https://utils.bot/info)")
	req.Header.Set("Accept", "text/html, application/xhtml+xml;q=0.9")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		for _, e := range []error{ErrBlocked, ErrThreats, ErrURL} {
			if errors.Is(err, e) {
				return Result{}, e
			}
		}
		return Result{}, ErrFetch
	}
	defer resp.Body.Close()
	typ, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (typ != "text/html" && typ != "application/xhtml+xml") {
		return Result{}, ErrType
	}
	if charset := strings.ToLower(params["charset"]); charset != "" && charset != "utf-8" && charset != "us-ascii" {
		return Result{}, ErrType
	}
	if encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); encoding != "" && encoding != "identity" {
		return Result{}, ErrType
	}
	if resp.ContentLength > MaxHTML {
		return Result{}, ErrSize
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxHTML+1))
	if err != nil {
		return Result{}, ErrFetch
	}
	if len(data) > MaxHTML {
		return Result{}, ErrSize
	}
	if !utf8.Valid(data) {
		return Result{}, ErrType
	}
	markdown, title, truncated, err := Convert(ctx, data, resp.Request.URL)
	if err != nil {
		return Result{}, err
	}
	return Result{URL: original.String(), FinalURL: resp.Request.URL.String(), SourceStatus: resp.StatusCode, Title: title, Markdown: markdown, Truncated: truncated, SourceBytes: len(data)}, nil
}
