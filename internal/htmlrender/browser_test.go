package htmlrender

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"pdfservice/internal/browser"
)

func TestBrowserBrokerRejectsUnsafeResourcesBeforeTransport(t *testing.T) {
	calls := 0
	b := &browserBroker{domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/html"}, "ok"), nil
	})}
	for _, r := range []browser.Request{
		{URL: "http://example.com/", Method: "GET"},
		{URL: "https://127.0.0.1/", Method: "GET"},
		{URL: "https://169.254.169.254/latest/meta-data/", Method: "GET"},
		{URL: "file:///proc/self/environ", Method: "GET"},
		{URL: "https://example.com/", Method: "POST"},
		{URL: "https://evil.example/", Method: "GET"},
		{URL: "https://sub.evil.example/", Method: "GET"},
	} {
		if _, err := b.Fetch(context.Background(), r); err == nil {
			t.Fatal("unsafe resource allowed", r)
		}
	}
	if calls != 0 {
		t.Fatal("unsafe resource reached network", calls)
	}
}
func TestBrowserBrokerRedirectHeadersAndBudgets(t *testing.T) {
	t.Run("no-credentials-or-cookies", func(t *testing.T) {
		b := &browserBroker{domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if len(r.Header) != 2 || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" {
				t.Fatal("headers forwarded", r.Header)
			}
			return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/html", "Set-Cookie": "sensitive-canary", "X-Secret": "private-canary"}, "hello"), nil
		})}
		got, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: "Document"})
		if err != nil || got.Headers["Set-Cookie"] != "" || got.Headers["X-Secret"] != "" {
			t.Fatal(got, err)
		}
	})
	t.Run("redirect-block", func(t *testing.T) {
		b := &browserBroker{domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			return browserHTTPResponse(r, 302, map[string]string{"Location": "https://evil.example/"}, ""), nil
		})}
		if _, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: "Document"}); !errors.Is(err, ErrBlocked) {
			t.Fatal(err)
		}
	})
	t.Run("aggregate", func(t *testing.T) {
		b := &browserBroker{total: MaxBrowserSource - 1, domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/javascript"}, "xx"), nil
		})}
		if _, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: "Script"}); !errors.Is(err, ErrSize) {
			t.Fatal(err)
		}
	})
	t.Run("count", func(t *testing.T) {
		b := &browserBroker{count: browser.MaxRequests, domains: snapshot(t, "evil.example"), transport: roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("over-budget transport invoked"); return nil, nil })}
		if _, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: "Script"}); !errors.Is(err, ErrComplexity) {
			t.Fatal(err)
		}
	})
	t.Run("compressed", func(t *testing.T) {
		b := &browserBroker{domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			return browserHTTPResponse(r, 200, map[string]string{"Content-Encoding": "gzip"}, "x"), nil
		})}
		if _, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: "Script"}); !errors.Is(err, ErrType) {
			t.Fatal(err)
		}
	})
}

func TestBrowserBrokerRefusesNetworkXMLBeforeReadingBody(t *testing.T) {
	for _, typ := range []string{"application/xml", "text/xml; charset=utf-8", "application/xhtml+xml", "image/svg+xml", "application/example+xml", "APPLICATION/XML"} {
		for _, resource := range []string{"Document", "Script", "Stylesheet", "XHR", "Fetch"} {
			t.Run(typ+"/"+resource, func(t *testing.T) {
				body := &trackedBody{Reader: strings.NewReader("untrusted-xml-body")}
				b := &browserBroker{domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					response := browserHTTPResponse(r, 200, map[string]string{"Content-Type": typ}, "")
					response.Body = body
					return response, nil
				})}
				if _, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: resource}); !errors.Is(err, ErrType) {
					t.Fatal("XML reached browser", err)
				}
				if body.read != 0 || body.closed != 1 || b.total != 0 {
					t.Fatal("rejected XML body consumed or leaked", body, b.total)
				}
			})
		}
	}
}

func TestBrowserBrokerEnforcesNoSniff(t *testing.T) {
	for _, supplied := range []string{"", "nosniff", "invalid"} {
		b := &browserBroker{domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/html", "X-Content-Type-Options": supplied}, "safe body"), nil
		})}
		got, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: "Document"})
		if err != nil || got.Headers["X-Content-Type-Options"] != "nosniff" {
			t.Fatal("source weakened MIME checks", got, err)
		}
	}
}

// Enabled only in the local Linux container with no external network. Destinations
// are synthetic and provided by an in-memory transport, never a live website.
func TestSandboxedBrowserIntegration(t *testing.T) {
	if os.Getenv("UTILS_BROWSER_TEST") != "1" {
		t.Skip("requires sandboxed Linux browser image")
	}
	renderer := BrowserFetcher{Launcher: "/opt/utils/browser-launch", Executable: "/usr/lib/chromium/chromium-headless-shell"}
	for _, tt := range []struct {
		name, source, want string
		fail               bool
	}{
		{"inline", `<title>JS</title><body><div id="a"></div><script>document.getElementById('a').textContent='executed-script'</script>`, "executed-script", false},
		{"multilingual", `<meta charset="utf-8"><body>日本語 العربية Ελληνικά 😀</body>`, "日本語 العربية Ελληνικά 😀", false},
		// Network XML refusal cannot establish absence of locally constructed XML
		// paths. Keep this normal script capability in the residual-risk review.
		{"local-xml-still-possible", `<body><script>document.body.textContent=new DOMParser().parseFromString('<root>local-xml-result</root>','text/xml').documentElement.textContent</script>`, "local-xml-result", false},
		{"webgl-disabled", `<body><script>document.body.textContent=document.createElement('canvas').getContext('webgl')===null?'gpu-disabled':'gpu-enabled'</script>`, "gpu-disabled", false},
		{"external", `<body><div id="a"></div><script src="/app.js"></script>`, "executed-external", false},
		{"blocked-script", `<body><script src="https://evil.example/app.js"></script>`, "", true},
		{"redirect-block", `<meta http-equiv="refresh" content="0;url=https://evil.example/"><body>moving</body>`, "", true},
		{"dom-limit", `<body><script>document.body.textContent="x".repeat(4194305)</script>`, "", true},
		{"private-fetch", `<body><script>fetch('https://127.0.0.1/').catch(()=>{})</script>`, "", true},
		{"fresh-storage", `<body><script>document.body.append(localStorage.getItem('secret')||'fresh-state');localStorage.setItem('secret','previous-job')</script>`, "fresh-state", false},
		{"fresh-storage-again", `<body><script>document.body.append(localStorage.getItem('secret')||'fresh-state')</script>`, "fresh-state", false},
		{"file-navigation", `<body><script>location.assign('file:///etc/passwd')</script>safe-source`, "safe-source", false},
		{"worker-block", `<body>workers-disabled<script>try{new Worker('data:text/javascript,postMessage(1)')}catch(e){}</script>`, "workers-disabled", false},
		{"socket-block", `<body>socket-disabled<script>try{new WebSocket('wss://127.0.0.1/')}catch(e){}</script>`, "socket-disabled", false},
		{"private-xhr", `<body><script>let x=new XMLHttpRequest();x.open('GET','https://169.254.169.254/');x.send()</script>`, "", true},
		{"post-denied", `<body>post-disabled<script>fetch('https://example.com/write',{method:'POST',body:'canary'}).catch(()=>{})</script>`, "post-disabled", false},
		{"iframe-block", `<body>frame-disabled<iframe src="https://127.0.0.1/"></iframe>`, "frame-disabled", false},
		{"navigation-budget", `<meta http-equiv="refresh" content="0;url=/"><body>loop</body>`, "", true},
		{"loop", `<body><script>while(true){}</script>`, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			transport := roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "example.com" {
					t.Fatal("unsafe destination reached transport")
				}
				source, typ := tt.source, "text/html"
				if r.URL.Path == "/app.js" {
					source = `document.getElementById('a').textContent='executed-external'`
					typ = "text/javascript"
				}
				return browserHTTPResponse(r, 200, map[string]string{"Content-Type": typ}, source), nil
			})
			got, err := renderer.fetch(ctx, "https://example.com/", snapshot(t, "evil.example"), transport)
			if tt.fail {
				if err == nil {
					t.Fatal("expected closed failure", got)
				}
				return
			}
			if err != nil || !got.JavaScript || !strings.Contains(got.Markdown, tt.want) {
				t.Fatal(got, err)
			}
		})
	}
}

func TestSandboxedBrowserDoesNotSniffScripts(t *testing.T) {
	if os.Getenv("UTILS_BROWSER_TEST") != "1" {
		t.Skip("requires sandboxed Linux browser image")
	}
	renderer := BrowserFetcher{Launcher: "/opt/utils/browser-launch", Executable: "/usr/lib/chromium/chromium-headless-shell"}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	transport := roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/wrong-type.js" {
			return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/plain"}, `document.body.textContent='sniffed-script-executed'`), nil
		}
		return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/html"}, `<body>original-document<script src="/wrong-type.js"></script>`), nil
	})
	got, err := renderer.fetch(ctx, "https://example.com/", snapshot(t, "evil.example"), transport)
	if err != nil || !strings.Contains(got.Markdown, "original-document") || strings.Contains(got.Markdown, "sniffed-script-executed") {
		t.Fatal("wrong-MIME script executed", got, err)
	}
}

func browserHTTPResponse(r *http.Request, status int, h map[string]string, body string) *http.Response {
	headers := http.Header{}
	for k, v := range h {
		headers.Set(k, v)
	}
	return response(r, status, headers, body)
}

func TestSandboxedBrowserRenderingTiming(t *testing.T) {
	if os.Getenv("UTILS_BROWSER_TEST") != "1" {
		t.Skip("requires sandboxed Linux browser image")
	}
	renderer := BrowserFetcher{Launcher: "/opt/utils/browser-launch", Executable: "/usr/lib/chromium/chromium-headless-shell"}
	for _, tt := range []struct {
		name, initial, next, want, absent string
		sourceDelay                       time.Duration
		min                               time.Duration
	}{
		{name: "wait-begins-after-load", initial: `<body><div id="a">initial</div><script>addEventListener('load',()=>setTimeout(()=>document.getElementById('a').textContent='after-load',200))</script>`, want: "after-load", sourceDelay: 300 * time.Millisecond, min: 1300 * time.Millisecond},
		{name: "navigation-restarts-grace", initial: `<body>first<script>addEventListener('load',()=>setTimeout(()=>location.assign('/next'),600))</script>`, next: `<body><div id="a">second</div><script>addEventListener('load',()=>setTimeout(()=>document.getElementById('a').textContent='second-page-ready',600))</script>`, want: "second-page-ready", min: 1600 * time.Millisecond},
		{name: "late-content-not-promised", initial: `<body><div id="a">initial-content</div><script>addEventListener('load',()=>setTimeout(()=>document.getElementById('a').textContent='too-late-content',2000))</script>`, want: "initial-content", absent: "too-late-content", min: time.Second},
		{name: "continuous-updates-do-not-wait-forever", initial: `<body><div id="a">initial</div><script>setInterval(()=>document.getElementById('a').textContent='timer-is-running',50)</script>`, want: "timer-is-running", min: time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			transport := roundTrip(func(r *http.Request) (*http.Response, error) {
				source := tt.initial
				if r.URL.Path == "/next" {
					source = tt.next
				} else if tt.sourceDelay > 0 {
					timer := time.NewTimer(tt.sourceDelay)
					defer timer.Stop()
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-timer.C:
					}
				}
				return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/html"}, source), nil
			})
			started := time.Now()
			got, err := renderer.fetch(ctx, "https://example.com/", snapshot(t, "evil.example"), transport)
			elapsed := time.Since(started)
			if err != nil || !strings.Contains(got.Markdown, tt.want) || tt.absent != "" && strings.Contains(got.Markdown, tt.absent) {
				t.Fatal(got, err)
			}
			if elapsed < tt.min {
				t.Fatal("captured before post-load grace", elapsed, tt.min)
			}
			if tt.next != "" && got.FinalURL != "https://example.com/next" {
				t.Fatal("wrong final page", got.FinalURL)
			}
		})
	}
}

func TestBrowserBrokerPreservesPrivateDNSBlock(t *testing.T) {
	b := &browserBroker{domains: snapshot(t, "evil.example"), transport: roundTrip(func(r *http.Request) (*http.Response, error) { return nil, ErrBlocked })}
	if _, err := b.Fetch(context.Background(), browser.Request{URL: "https://example.com/", Method: "GET", Type: "Document"}); !errors.Is(err, ErrBlocked) {
		t.Fatal("DNS block became generic failure", err)
	}
}

func TestSandboxedBrowserOwnDeadlineIsDocumentFailure(t *testing.T) {
	if os.Getenv("UTILS_BROWSER_TEST") != "1" {
		t.Skip("requires sandboxed Linux browser image")
	}
	renderer := BrowserFetcher{Launcher: "/opt/utils/browser-launch", Executable: "/usr/lib/chromium/chromium-headless-shell"}
	ctx, cancel := context.WithTimeout(context.Background(), 19*time.Second)
	defer cancel()
	transport := roundTrip(func(r *http.Request) (*http.Response, error) {
		return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/html"}, `<script>while(true){}</script>`), nil
	})
	_, err := renderer.fetch(ctx, "https://example.com/", snapshot(t, "evil.example"), transport)
	if !errors.Is(err, ErrComplexity) || ctx.Err() != nil {
		t.Fatal("document exhausted render budget without failure attribution", err, ctx.Err())
	}
}

func TestSandboxedBrowserSnapshotLifecycle(t *testing.T) {
	if os.Getenv("UTILS_BROWSER_TEST") != "1" {
		t.Skip("requires sandboxed Linux browser image")
	}
	warm := &browser.Warm{Launcher: "/opt/utils/browser-launch", Executable: "/usr/lib/chromium/chromium-headless-shell"}
	defer warm.Close()
	build, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := warm.Prepare(build); err != nil {
		t.Fatal("snapshot preparation", err)
	}
	cancel() // Build-hook deadline must never kill the browser saved in the image.
	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if warm.Prepare(ctx) != nil || warm.Restore(ctx) != nil || warm.Validate(ctx) != nil || warm.Restore(ctx) != nil {
		t.Fatal("blank browser did not survive lifecycle")
	}
	renderer := BrowserFetcher{Warm: warm}
	transport := roundTrip(func(r *http.Request) (*http.Response, error) {
		return browserHTTPResponse(r, 200, map[string]string{"Content-Type": "text/html"}, `<body><script>document.body.textContent=(localStorage.getItem('secret')||'fresh-customer-context')+' '+crypto.randomUUID();localStorage.setItem('secret','private-customer-canary')</script>`), nil
	})
	got, err := renderer.fetch(ctx, "https://example.com/", snapshot(t, "evil.example"), transport)
	if err != nil || !strings.Contains(got.Markdown, "fresh-customer-context") || strings.Contains(got.Markdown, "renderer-ready") {
		t.Fatal("customer-free context", err)
	}
	if warm.Restore(ctx) == nil || warm.Prepare(ctx) == nil {
		t.Fatal("consumed browser reusable")
	}
	if _, err := renderer.fetch(ctx, "https://example.com/", snapshot(t, "evil.example"), transport); err == nil {
		t.Fatal("second customer admitted")
	}
}
