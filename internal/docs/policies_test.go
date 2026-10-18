package docs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"pdfservice/internal/protocol"
)

func TestInformationPageAndOldPolicyLinkRemainReachable(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/disclaimers", nil))
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "/info" {
		t.Fatal("old policy URL must redirect to information")
	}
	for _, path := range []string{"/info", "/terms", "/openapi", "/openapi/json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		body := w.Body.String()
		if path == "/info" || path == "/terms" {
			other := "/terms"
			if path == "/terms" {
				other = "/info"
			}
			peer := httptest.NewRecorder()
			h.ServeHTTP(peer, httptest.NewRequest("GET", other, nil))
			body += peer.Body.String()
		}
		for _, required := range []string{"Parsing failures are not charged", "Automatic refunds are not enabled yet", "Privacy", "Terms of use", "Copyright", "info@utils.bot"} {
			if w.Code != 200 || !strings.Contains(body, required) {
				t.Fatalf("%s missing accurate common policy %q", path, required)
			}
		}
		if strings.Contains(w.Body.String(), "Payments are ordinarily nonrefundable") || strings.Contains(w.Body.String(), "No refunds") {
			t.Fatal("superseded policy remains")
		}
	}
}

func TestContractNoticeAndIllinoisPoliciesMatchHumanAndAgentRepresentations(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, path := range []string{"/info", "/openapi", "/openapi/json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		body := w.Body.String()
		if path == "/info" {
			peer := httptest.NewRecorder()
			h.ServeHTTP(peer, httptest.NewRequest("GET", "/terms", nil))
			body += peer.Body.String()
			// The complete technical specification retains per-operation
			// wording that the shorter documents intentionally do not repeat.
			peer = httptest.NewRecorder()
			h.ServeHTTP(peer, httptest.NewRequest("GET", "/openapi/json", nil))
			body += peer.Body.String()
		}
		for _, required := range []string{
			"Terms version " + protocol.TermsVersion,
			"Submitting a PDF with payment authorization indicates",
			"successfully parsed blank or image-only PDF",
			"Illinois Personal Information Protection Act",
			"immediately following discovery",
			"Illinois Attorney General",
			"Payment-provider approval is not a legal authorization",
			"collect the full quoted fee",
			"truncated: true",
			"Each distinct payment authorization",
			"No discount or refund is provided solely",
			"fraud, willful misconduct, gross negligence",
			"does not impose a consumer indemnity",
			"no mandatory arbitration",
			"greater of US$100",
		} {
			if w.Code != 200 || !strings.Contains(body, required) {
				t.Fatalf("%s missing shared policy %q", path, required)
			}
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/openapi/json", nil))
	var spec struct {
		Version string `json:"x-terms-version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil || spec.Version != protocol.TermsVersion {
		t.Fatal("quote and contract versions differ", err)
	}
	quote := (protocol.Config{}).Quote("https://utils.bot/v1/pdf/text")
	if !strings.Contains(quote.Resource.Description, "Terms "+spec.Version+": https://utils.bot/terms#terms-of-use") {
		t.Fatal("initial payment quote omitted the versioned contractual notice")
	}
}

func TestFirstPartyPagesRemainLightweightAndProtectOperatorIdentity(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, path := range []string{"/", "/info", "/terms", "/readme", "/docs", "/openapi", "/openapi/json", "/llms.txt"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		body := w.Body.String()
		if regexp.MustCompile(`\b[0-9]{12}\b`).MatchString(body) {
			t.Fatal("public content discloses an AWS account")
		}
		for _, forbidden := range []string{"/Users/", "@gmail.com", "@icloud.com"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s discloses private operator setting", path)
			}
		}
	}
	css, _ := files.ReadFile("assets/site.css")
	if len(css) > 4096 || strings.Contains(string(css), "@import") || strings.Contains(string(css), "url(") {
		t.Fatal("site styling should stay small and self-contained")
	}
	if !strings.Contains(string(css), "focus-visible") || !strings.Contains(string(css), "@media") {
		t.Fatal("keyboard focus or mobile layout missing")
	}
}

func TestRequesterPrivacyDisclosuresMatchAllPolicyRepresentations(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, path := range []string{"/info", "/openapi", "/openapi/json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		for _, text := range []string{"We do not collect customer names", "We do not record requester IP addresses", "WAF request sampling are disabled", "fourteen-day retention ceiling", "physically deletes expired data asynchronously", "pseudonymous"} {
			if w.Code != 200 || !strings.Contains(w.Body.String(), text) {
				t.Fatalf("%s missing accurate privacy policy %q", path, text)
			}
		}
	}
}

func TestFailedParseQuotaIsDisclosedAlongsidePrivacyAndPaymentTerms(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, path := range []string{"/info", "/openapi", "/openapi/json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		for _, notice := range []string{"Five document failures, completed-but-unpaid attempts or abandoned verified requests per wallet per fixed one-hour window", "Successful purchases and service failures do not", "Already-admitted work may finish", "Hashed-wallet/payment abuse counters and hashed event IDs expire", "No raw wallet address", "TTL deletion is asynchronous"} {
			if !strings.Contains(w.Body.String(), notice) {
				t.Fatalf("%s omits quota or its privacy implications: %s", path, notice)
			}
		}
	}
	quote := (protocol.Config{}).Quote("https://utils.bot/v1/pdf/text")
	if !strings.Contains(quote.Resource.Description, "Five failed/unpaid attempts or abandoned verified requests per wallet per fixed one-hour window") || !strings.Contains(quote.Resource.Description, "Retry-After on 429") {
		t.Fatal("payment quote omitted the failed-parse admission limit")
	}
}

func TestEveryPublishedTermsReferenceUsesCurrentVersion(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	version := regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}-r[0-9]+`)
	for _, path := range []string{"/", "/info", "/terms", "/readme", "/docs", "/openapi", "/openapi/json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s status %d", path, w.Code)
		}
		for _, found := range version.FindAllString(w.Body.String(), -1) {
			if found != protocol.TermsVersion {
				t.Fatalf("%s has stale terms reference %s", path, found)
			}
		}
	}
}

func TestPDFAuthorizationTimeBudgetIsDisclosedPerOperation(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, path := range []string{"/openapi", "/openapi/json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		for _, notice := range []string{"90 seconds remaining before upload", "45 seconds before parsing", "180-second authorization window", "Confirmed paid retries are exempt"} {
			if !strings.Contains(w.Body.String(), notice) {
				t.Fatalf("%s lacks %q", path, notice)
			}
		}
	}
}

func TestTermsCoverToolsAndURLSourceBehaviorWithoutAdvertisingAnUnreleasedRoute(t *testing.T) {
	h := New("https://utils.bot/v1/pdf/text")
	for _, path := range []string{"/terms", "/openapi", "/openapi/json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		for _, required := range []string{
			"selected operation's", "login", "error page", "no identical fetched content",
			"no JavaScript", "uncharged", "Mandatory", "no mandatory arbitration",
		} {
			if !strings.Contains(strings.ToLower(w.Body.String()), strings.ToLower(required)) {
				t.Fatalf("%s omits generic tool terms: %s", path, required)
			}
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/openapi/json", nil))
	var spec struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	for path := range spec.Paths {
		if strings.Contains(path, "/html") || strings.Contains(path, "/url") || strings.Contains(path, "/ocr") || strings.Contains(path, "/csv") {
			t.Fatal("unreleased tool advertised", path)
		}
	}
}
