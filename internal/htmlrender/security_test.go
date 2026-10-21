package htmlrender

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func snapshot(t *testing.T, domains ...string) *Snapshot {
	t.Helper()
	var hashes [][32]byte
	for _, s := range domains {
		hashes = append(hashes, sha256.Sum256([]byte(s)))
	}
	data, err := EncodeSnapshot(hashes, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := DecodeSnapshot(data, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestCanonicalURLRejectsAmbiguousAndPrivateTargets(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://127.0.0.1", "https://[::ffff:127.0.0.1]", "https://169.254.169.254/latest/meta-data", "https://example.com:444/", "https://user:pass@example.com/", "https://example.com\\@evil.com", "https://example.com/%0a\n", "https://localhost", "https://x.local", "https://s3.us-east-2.amazonaws.com/", "https://example.com?", "https://0177.0.0.1/", "https://example.com:/"} {
		if got, err := CanonicalURL(raw); err == nil {
			t.Errorf("accepted %q: %s", raw, got)
		}
	}
	u, err := CanonicalURL("https://EXAMPLE.com.:443/a?q=1#part")
	if err != nil || u.String() != "https://example.com/a?q=1" {
		t.Fatal(u, err)
	}
}
func TestSpecialAddressRanges(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.100.100.200", "169.254.170.2", "172.16.0.1", "192.0.0.8", "192.168.0.1", "198.19.0.1", "203.0.113.1", "224.1.2.3", "255.255.255.255", "::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "2002:7f00:1::", "fd00::1", "fe80::1"} {
		if publicAddress(netip.MustParseAddr(raw)) {
			t.Error("allowed", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(raw)) {
			t.Error("blocked", raw)
		}
	}
}

type dnsStub struct {
	ips   []netip.Addr
	calls int
}

func (d *dnsStub) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	d.calls++
	if d.calls > 1 {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return d.ips, nil
}

type dialStub struct{ addresses []string }

func (d *dialStub) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, address)
	a, b := net.Pipe()
	b.Close()
	return a, nil
}
func TestDNSMixedAnswersAndRebinding(t *testing.T) {
	dns := &dnsStub{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}}
	dial := &dialStub{}
	if _, err := publicDial(dns, dial)(context.Background(), "tcp", "example.com:443"); !errors.Is(err, ErrBlocked) || len(dial.addresses) != 0 {
		t.Fatal("mixed answer escaped", err, dial.addresses)
	}
	dns = &dnsStub{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	dial = &dialStub{}
	conn, err := publicDial(dns, dial)(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if dns.calls != 1 || len(dial.addresses) != 1 || dial.addresses[0] != "8.8.8.8:443" {
		t.Fatal("second DNS lookup or unpinned connection", dns.calls, dial.addresses)
	}
}
func TestThreatMatchingFreshnessAndIntegrity(t *testing.T) {
	now := time.Now()
	s := snapshot(t, "evil.example", "phish.example", "z.example")
	for _, host := range []string{"evil.example", "a.evil.example", "PHISH.EXAMPLE."} {
		if !errors.Is(s.Check(context.Background(), host, now), ErrBlocked) {
			t.Error("not blocked", host)
		}
	}
	for _, host := range []string{"notevil.example", "evil.example.org", "example.com"} {
		if err := s.Check(context.Background(), host, now); err != nil {
			t.Error(host, err)
		}
	}
	if !errors.Is(s.Check(context.Background(), "example.com", now.Add(25*time.Hour)), ErrThreats) {
		t.Fatal("stale list used")
	}
	data, _ := EncodeSnapshot([][32]byte{sha256.Sum256([]byte("a.example"))}, now)
	data[len(data)-1] ^= 1
	if _, err := DecodeSnapshot(data, now); err == nil {
		t.Fatal("corrupt snapshot accepted")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(r *http.Request, status int, headers http.Header, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r, ContentLength: int64(len(body))}
}
func TestRedirectCannotReachBlockedHostOrMetadata(t *testing.T) {
	for _, target := range []string{"https://evil.example/", "https://169.254.169.254/", "http://example.com/"} {
		calls := 0
		_, err := fetch(context.Background(), "https://example.com/start", snapshot(t, "evil.example"), roundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			return response(r, 302, http.Header{"Location": {target}}, ""), nil
		}))
		if err == nil || calls != 1 {
			t.Fatal("redirect connected", target, calls, err)
		}
	}
}
func TestFetchOnlyOneHTMLResourceAndNoCredentialForwarding(t *testing.T) {
	calls := 0
	result, err := fetch(context.Background(), "https://example.com/start", snapshot(t, "evil.example"), roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		for _, h := range []string{"Authorization", "Cookie", "PAYMENT-SIGNATURE", "Referer"} {
			if r.Header.Get(h) != "" {
				t.Error("forwarded", h)
			}
		}
		if calls == 1 {
			return response(r, 302, http.Header{"Location": {"https://other.example/login"}, "Set-Cookie": {"secret=x"}}, ""), nil
		}
		return response(r, 403, http.Header{"Content-Type": {"text/html; charset=utf-8"}}, `<title>Login</title><h1>Sign in</h1><script>private script</script><img src="https://evil.example/tracker"><iframe src="https://evil.example"></iframe>`), nil
	}))
	if err != nil || calls != 2 || result.SourceStatus != 403 || result.Title != "Login" || strings.Contains(result.Markdown, "private script") || result.JavaScript {
		t.Fatal(result, calls, err)
	}
}
func TestFetchRejectsMimeEncodingOversizeAndUnavailableFeed(t *testing.T) {
	for _, headers := range []http.Header{{"Content-Type": {"application/pdf"}}, {"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}}, {"Content-Type": {"text/html; charset=windows-1252"}}} {
		_, err := fetch(context.Background(), "https://example.com", snapshot(t, "evil.example"), roundTrip(func(r *http.Request) (*http.Response, error) { return response(r, 200, headers, "hello"), nil }))
		if !errors.Is(err, ErrType) {
			t.Fatal(err)
		}
	}
	_, err := fetch(context.Background(), "https://example.com", snapshot(t, "evil.example"), roundTrip(func(r *http.Request) (*http.Response, error) {
		return response(r, 200, http.Header{"Content-Type": {"text/html"}}, strings.Repeat("x", MaxHTML+1)), nil
	}))
	if !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	calls := 0
	_, err = fetch(context.Background(), "https://example.com", nil, roundTrip(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("canary") }))
	if !errors.Is(err, ErrThreats) || calls != 0 {
		t.Fatal(err, calls)
	}
}
func TestConversionBoundsAndNoScriptExecution(t *testing.T) {
	base, _ := url.Parse("https://example.com/page")
	md, title, partial, err := Convert(context.Background(), []byte(`<title>Test</title><h1>Hello</h1><p>A <a href="/x">link</a>.</p><ul><li>One</li><li>Two</li></ul><script>canary()</script><a href="javascript:alert(1)">safe text</a>`), base)
	if err != nil || title != "Test" || partial || !strings.Contains(md, "# Hello") || !strings.Contains(md, "[link](https://example.com/x)") || strings.Contains(md, "canary") || strings.Contains(md, "javascript:") {
		t.Fatal(md, title, partial, err)
	}
	// Relative links can expand beyond the source size. Exercise the output
	// limit without violating the independent four-MiB source limit first.
	longBase, _ := url.Parse("https://example.com/" + strings.Repeat("a", 1800) + "/")
	_, _, partial, err = Convert(context.Background(), []byte(strings.Repeat(`<a href="x">a</a>`, MaxMarkdown/1800+2)), longBase)
	if err != nil || !partial {
		t.Fatal(partial, err)
	}
	_, _, _, err = Convert(context.Background(), []byte(strings.Repeat("<p>x</p>", 100001)), base)
	if !errors.Is(err, ErrComplexity) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err = Convert(ctx, []byte("x"), base); err == nil {
		t.Fatal("ignored cancellation")
	}
}
func TestRefreshUpdatesDynamicallyAndRejectsBrokenFeeds(t *testing.T) {
	old := feedSources
	defer func() { feedSources = old }()
	feedSources = append([]struct {
		URL    string
		Min    int
		Hagezi bool
	}(nil), old...)
	for i := range feedSources {
		feedSources[i].Min = 1
	}
	now := time.Now().UTC().Truncate(time.Minute)
	domain := "old.example"
	broken := false
	transport := roundTrip(func(r *http.Request) (*http.Response, error) {
		if broken {
			return response(r, 200, nil, "<!doctype html>upstream error"), nil
		}
		body := domain + "\n"
		if strings.Contains(r.URL.Host, "githubusercontent") {
			body = "# Number of entries: 1\n# Last modified: " + now.Format("2 Jan 2006 15:04 MST") + "\n" + body
		}
		return response(r, 200, http.Header{"Last-Modified": {now.Format(http.TimeFormat)}}, body), nil
	})
	for _, next := range []string{"old.example", "new.example"} {
		domain = next
		data, err := Refresh(context.Background(), transport, now)
		if err != nil {
			t.Fatal(err)
		}
		s, err := DecodeSnapshot(data, now)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(s.Check(context.Background(), domain, now), ErrBlocked) {
			t.Fatal("update ignored")
		}
		if next == "new.example" && s.Check(context.Background(), "old.example", now) != nil {
			t.Fatal("removed domain still blocked")
		}
	}
	broken = true
	if _, err := Refresh(context.Background(), transport, now); err == nil {
		t.Fatal("published broken update")
	}
	var hashes [][32]byte
	if err := parseFeed(strings.NewReader("old.example\n"), 1, false, now.Add(-73*time.Hour), now, &hashes); err == nil {
		t.Fatal("stale source refreshed")
	}
}
func FuzzURLAndHTML(f *testing.F) {
	f.Add("https://example.com/a", []byte("<h1>Hello</h1>"))
	f.Add("https://127.0.0.1", []byte("<script>x</script>"))
	f.Fuzz(func(t *testing.T, raw string, body []byte) {
		if len(body) > MaxHTML {
			return
		}
		u, err := CanonicalURL(raw)
		if err != nil {
			return
		}
		if _, err := CanonicalURL(u.String()); err != nil {
			t.Fatal("canonicalization not stable")
		}
		md, _, _, err := Convert(context.Background(), body, u)
		if err == nil && len(md) > MaxMarkdown {
			t.Fatal("output escaped bound")
		}
	})
}
func TestWorkerContainsPanicAndBoundsWire(t *testing.T) {
	w := Worker{Load: func(context.Context) (DomainCheck, error) { panic("private canary") }}
	data, err := w.Invoke(context.Background(), []byte(`{"url":"https://example.com/"}`))
	if err != nil || bytes.Contains(data, []byte("canary")) {
		t.Fatal(string(data), err)
	}
	for _, raw := range []string{`{"url":"https://example.com","url":"https://evil.example"}`, `{"url":"https://example.com","options":true}`} {
		data, _ := w.Invoke(context.Background(), []byte(raw))
		var out Result
		json.Unmarshal(data, &out)
		if out.Error != ErrURL.Error() {
			t.Fatal(string(data))
		}
	}
}

func TestHageziTruncationCannotBecomeAFreshSnapshot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Minute)
	text := "# Number of entries: 2\n# Last modified: " + now.Format("2 Jan 2006 15:04 MST") + "\nevil.example\n"
	var hashes [][32]byte
	if err := parseFeed(strings.NewReader(text), 1, true, time.Time{}, now, &hashes); err == nil {
		t.Fatal("accepted truncated publisher-declared list")
	}
}

func TestURLBoundsRejectExcessiveLabelsAndExpandedEncoding(t *testing.T) {
	if _, err := CanonicalURL("https://" + strings.Repeat("a.", 8) + "example.com/"); err != nil {
		t.Fatal("maximum supported hostname labels rejected", err)
	}
	for _, raw := range []string{"https://" + strings.Repeat("a.", 10) + "example.com/", "https://example.com/" + strings.Repeat("界", 2000)} {
		if _, err := CanonicalURL(raw); err == nil {
			t.Fatal("URL escaped canonical bounds")
		}
	}
}

func TestSourceTextCannotTurnGeneratedLinkIntoRemoteImage(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	markdown, _, _, err := Convert(context.Background(), []byte(`!<a href="https://tracker.example/pixel">image</a>`), base)
	if err != nil || !strings.HasPrefix(markdown, `\![image](`) {
		t.Fatal("source text created active image syntax", markdown, err)
	}
}

func FuzzCanonicalURLStaysCanonical(f *testing.F) {
	for _, seed := range []string{"https://example.com/a?q=1#frag", "https://example.com.:443/", "https://127.0.0.1/", "https://[::1]/", "https://example.com\\@127.0.0.1/", "https://example.com/%2f%2e%2e/"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := CanonicalURL(raw)
		if err != nil {
			return
		}
		again, err := CanonicalURL(u.String())
		if err != nil || again.String() != u.String() || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" || !domainName(u.Hostname()) {
			t.Fatal("unsafe normalization", u, err)
		}
	})
}
