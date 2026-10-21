package htmlrender

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"pdfservice/internal/jsonwire"
)

func vmRequest(s *VMServer, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestMicroVMOnlyOneJobAndNoLifecycleReset(t *testing.T) {
	var calls atomic.Int32
	s := &VMServer{Probe: true, SelfTest: func(context.Context) error { calls.Add(1); return nil }}
	if vmRequest(s, hookPrefix+"ready", `{}`).Code != 200 || vmRequest(s, hookPrefix+"validate", `{}`).Code != 200 {
		t.Fatal("image initialization failed")
	}
	var group sync.WaitGroup
	var successful atomic.Int32
	for range 10 {
		group.Go(func() {
			if vmRequest(s, "/convert", `{}`).Code == 200 {
				successful.Add(1)
			}
		})
	}
	group.Wait()
	if successful.Load() != 1 || calls.Load() != 3 {
		t.Fatal("shared or duplicated job", successful.Load(), calls.Load())
	}
	if vmRequest(s, hookPrefix+"run", `{"microvmId":"mvm-test"}`).Code != 404 {
		t.Fatal("hook reset consumed VM")
	}
	if vmRequest(s, hookPrefix+"ready", `{}`).Code != 503 {
		t.Fatal("customer-modified VM could be reused as base")
	}
}
func TestProbeCannotAcceptCustomerURL(t *testing.T) {
	s := &VMServer{Probe: true, SelfTest: func(context.Context) error { t.Fatal("customer input reached browser"); return nil }}
	if vmRequest(s, "/convert", `{"url":"https://customer-canary.example/"}`).Code != 400 {
		t.Fatal("probe accepted customer URL")
	}
}
func TestNoCustomerContentInRunHook(t *testing.T) {
	for _, body := range []string{`{"microvmId":"mvm-test","runHookPayload":"customer-canary"}`, `{"microvmId":"mvm-test","url":"https://example.com"}`, `{"microvmId":"mvm-test","MicrovmId":"another"}`} {
		s := &VMServer{}
		if vmRequest(s, hookPrefix+"run", body).Code != 404 || s.phase.Load() != 0 {
			t.Fatal("unsafe hook input")
		}
	}
}
func TestThreatReadCapabilityCannotFetchArbitraryURL(t *testing.T) {
	key := GenerationPrefix + strings.Repeat("a", 64) + "/00.bin"
	valid := "https://threat-fixture.s3.us-east-2.amazonaws.com/" + key + "?X-Amz-Signature=signature"
	if !ThreatLink(valid, "threat-fixture", key) {
		t.Fatal("valid threat capability rejected")
	}
	for _, raw := range []string{strings.Replace(valid, "https:", "http:", 1), strings.Replace(valid, "threat-fixture.s3.us-east-2.amazonaws.com", "evil.example", 1), valid + "#fragment", strings.Replace(valid, "/00.bin", "/01.bin", 1), strings.Replace(valid, "https://", "https://user:password@", 1)} {
		if ThreatLink(raw, "threat-fixture", key) {
			t.Fatal("threat URL escaped pinned object scope")
		}
	}
}
func TestResultCannotCarryHTMLBinaryOrExtraFields(t *testing.T) {
	for _, raw := range []string{`{"markdown":"hello","extra":"unexpected"}`, `{"markdown":"hello","Markdown":"other"}`, "\xff"} {
		var r Result
		if jsonwire.Decode([]byte(raw), &r, MaxResult) == nil {
			t.Fatal("invalid worker schema accepted")
		}
	}
	// HTML and terminal sequences inside code blocks must also be escaped or
	// removed, not exempted as trusted source code.
	r := prepareResult(Result{Markdown: "````\n</script><img src=x onerror=evil>\x1b[2J\n````", Title: "\u202eevil"})
	if strings.ContainsAny(r.Markdown, "<>\x1b") || !safeText(r.Markdown) || !safeText(r.Title) {
		t.Fatal("unsafe fenced content")
	}
}

func TestLifecycleUsesSnapshotValidationWithoutRunHook(t *testing.T) {
	prepare, validate := 0, 0
	s := &VMServer{SelfTest: func(context.Context) error { prepare++; return nil }, Validate: func(context.Context) error { validate++; return nil }}
	for _, path := range []string{hookPrefix + "ready", hookPrefix + "validate"} {
		if got := vmRequest(s, path, `{}`).Code; got != 200 {
			t.Fatal(path, got)
		}
	}
	if prepare != 1 || validate != 1 {
		t.Fatal("wrong image lifecycle", prepare, validate)
	}
	if vmRequest(s, hookPrefix+"run", `{"microvmId":"mvm-test"}`).Code != 404 {
		t.Fatal("unexpected per-request initialization")
	}
}

func TestProbeExercisesRestoredBrowserValidation(t *testing.T) {
	calls := 0
	s := &VMServer{Probe: true, SelfTest: func(context.Context) error { t.Fatal("preparation is not a render proof"); return nil }, Validate: func(context.Context) error { calls++; return nil }}
	if vmRequest(s, "/convert", `{}`).Code != 200 || calls != 1 {
		t.Fatal("probe skipped actual restored renderer")
	}
}
