package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const MaxRequests = 48
const MaxDOM = 4 << 20

// Settle is extra time after the latest page load, not a total JS execution limit.
const Settle = time.Second

var ErrLimit = errors.New("browser_limit")

type Request struct{ URL, Method, Type string }
type Response struct {
	Status  int
	Headers map[string]string
	Body    []byte
}
type Fetch func(context.Context, Request) (Response, error)
type Rendered struct {
	HTML     string
	URL      string
	RenderMS int64
}

// Render creates its customer context after VM restore, in a one-job browser. Every permitted resource is
// fulfilled by the trusted broker. The browser has no Internet socket access.
func Render(ctx context.Context, s *Session, raw string, fetch Fetch) (Rendered, error) {
	started := time.Now()
	// Never use the default context inherited from a customer-free snapshot.
	var fresh struct {
		ID string `json:"browserContextId"`
	}
	if s.Call(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}, &fresh) != nil || fresh.ID == "" {
		return Rendered{}, ErrBrowser
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = s.Call(cleanup, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": fresh.ID}, nil)
	}()
	var target struct {
		TargetID string `json:"targetId"`
	}
	if s.Call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank", "browserContextId": fresh.ID}, &target) != nil {
		return Rendered{}, ErrBrowser
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if s.Call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}, &attached) != nil {
		return Rendered{}, ErrBrowser
	}
	sid := attached.SessionID
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = s.Call(cleanup, "", "Target.closeTarget", map[string]any{"targetId": target.TargetID}, nil)
	}()
	for _, command := range []struct {
		method string
		params any
	}{
		{"Page.enable", map[string]any{}},
		{"Network.setBypassServiceWorker", map[string]any{"bypass": true}},
		{"Browser.setDownloadBehavior", map[string]any{"behavior": "deny"}},
		{"Fetch.enable", map[string]any{"patterns": []any{map[string]any{"urlPattern": "*", "requestStage": "Request"}}, "handleAuthRequests": false}},
	} {
		if s.Call(ctx, sid, command.method, command.params, nil) != nil {
			return Rendered{}, ErrBrowser
		}
	}
	var frames struct {
		FrameTree struct {
			Frame struct {
				ID string `json:"id"`
			} `json:"frame"`
		} `json:"frameTree"`
	}
	if s.Call(ctx, sid, "Page.getFrameTree", nil, &frames) != nil {
		return Rendered{}, ErrBrowser
	}
	// Do not synchronously await Page.navigate: paused network requests must be
	// serviced while Chromium is navigating. Its command reply is still drained.
	navDone := make(chan error, 1)
	go func() { navDone <- s.Call(ctx, sid, "Page.navigate", map[string]any{"url": raw}, nil) }()
	var settled <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	requests, documents := 0, 0
	redirects := map[string]int{}
	final := raw
	for {
		select {
		case <-ctx.Done():
			return Rendered{}, ErrBrowser
		case <-s.done:
			return Rendered{}, ErrBrowser
		case err := <-navDone:
			if err != nil {
				return Rendered{}, ErrBrowser
			}
			navDone = nil
		case <-settled:
			// Bound serialization before transporting DOM through the debugging pipe.
			expression := `(()=>{const e=document.documentElement;if(!e)return {html:"",url:location.href};const h=e.outerHTML;if(h.length>4194304)return {limit:true};return {html:h,url:location.href}})()`
			var evaluation struct {
				Result struct {
					Value struct {
						HTML  string `json:"html"`
						URL   string `json:"url"`
						Limit bool   `json:"limit"`
					} `json:"value"`
				} `json:"result"`
				Exception json.RawMessage `json:"exceptionDetails"`
			}
			if s.Call(ctx, sid, "Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true, "timeout": 1000}, &evaluation) != nil || len(evaluation.Exception) > 0 {
				return Rendered{}, ErrBrowser
			}
			v := evaluation.Result.Value
			if v.Limit || len(v.HTML) > MaxDOM {
				return Rendered{}, ErrLimit
			}
			// A history update is not a separately fetched page, but must still be
			// validated by the caller before it is returned as the final URL.
			if v.URL != "" {
				final = v.URL
			}
			return Rendered{HTML: v.HTML, URL: final, RenderMS: time.Since(started).Milliseconds()}, nil
		case event := <-s.events:
			if event.Session != sid {
				continue
			}
			if event.Method == "Page.loadEventFired" {
				if timer == nil {
					timer = time.NewTimer(Settle)
				} else {
					timer.Reset(Settle)
				}
				settled = timer.C
				continue
			}
			if event.Method != "Fetch.requestPaused" {
				continue
			}
			var paused struct {
				ID         string `json:"requestId"`
				Redirected string `json:"redirectedRequestId"`
				FrameID    string `json:"frameId"`
				Type       string `json:"resourceType"`
				Request    struct {
					URL    string `json:"url"`
					Method string `json:"method"`
				} `json:"request"`
			}
			if json.Unmarshal(event.Params, &paused) != nil || paused.ID == "" {
				return Rendered{}, ErrBrowser
			}
			depth := 0
			if paused.Redirected != "" {
				depth = redirects[paused.Redirected] + 1
				delete(redirects, paused.Redirected)
			}
			if depth > 4 {
				return Rendered{}, ErrLimit
			}
			redirects[paused.ID] = depth
			requests++
			if requests > MaxRequests {
				return Rendered{}, ErrLimit
			}
			fail := func() error {
				return s.Call(ctx, sid, "Fetch.failRequest", map[string]any{"requestId": paused.ID, "errorReason": "BlockedByClient"}, nil)
			}
			if paused.FrameID != frames.FrameTree.Frame.ID || paused.Request.Method != "GET" || !resourceAllowed(paused.Type) {
				if fail() != nil {
					return Rendered{}, ErrBrowser
				}
				continue
			}
			if paused.Type == "Document" {
				// A navigation starts a new page. Never reuse a previous page's
				// post-load timer to capture the new document prematurely.
				if timer != nil {
					timer.Stop()
					timer = nil
					settled = nil
				}
				documents++
				if documents > 5 {
					return Rendered{}, ErrLimit
				}
				final = paused.Request.URL
			}
			response, err := fetch(ctx, Request{URL: paused.Request.URL, Method: paused.Request.Method, Type: paused.Type})
			if err != nil {
				return Rendered{}, err
			}
			headers := []map[string]string{}
			for name, value := range response.Headers {
				headers = append(headers, map[string]string{"name": name, "value": value})
			}
			// This additional policy restricts browsing features, while preserving any
			// stricter policy supplied by the website. No worker/iframe/plugin jobs.
			headers = append(headers, map[string]string{"name": "Content-Security-Policy", "value": "worker-src 'none'; frame-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'"})
			if s.Call(ctx, sid, "Fetch.fulfillRequest", map[string]any{"requestId": paused.ID, "responseCode": response.Status, "responseHeaders": headers, "body": base64.StdEncoding.EncodeToString(response.Body)}, nil) != nil {
				return Rendered{}, ErrBrowser
			}
		}
	}
}
func resourceAllowed(typ string) bool {
	switch typ {
	case "Document", "Script", "Stylesheet", "XHR", "Fetch":
		return true
	}
	return false
}
