package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHTMLUnfixedNativeFindingsBlockRelease(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"findings":[]}`, `{"findings":[{"status":"unfixed"}]}`,
		`{"findings":[{"status":"isolated"}]}`, `{"findings":[{"status":"fixed"}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"vendor_disputed","version":"2"}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"bounded","version":"2"}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"risk_accepted","version":"2"}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"code_path_absent","version":"2"}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"reviewed_not_security","version":"2"}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"component_absent","forbidden":["tool"]}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"component_absent","version":"2","forbidden":[]}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"component_absent","version":"2","forbidden":[""]}]}`,
		`{"findings":[{"package":"libx","cve":"CVE-test","status":"unfixed"},{"package":"libx","cve":"CVE-test","status":"fixed","version":"2"}]}`,
	} {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if requireHTMLNativeReview(path) == nil {
			t.Fatal("invalid or unfixed policy permitted public HTML release", body)
		}
	}
	if requireHTMLNativeReview(filepath.Join(t.TempDir(), "missing")) == nil {
		t.Fatal("missing review permitted release")
	}
}

func TestHTMLReviewedFixedAndAbsentPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"findings":[{"package":"libx","cve":"CVE-test-1","status":"fixed","version":"2+patched"},{"package":"libx","cve":"CVE-test-2","status":"component_absent","version":"2+patched","forbidden":["unused-tool"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireHTMLNativeReview(path); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentHTMLPolicyHasExplicitNativeReviews(t *testing.T) {
	if err := requireHTMLNativeReview("../native/browser-advisories.json"); err != nil {
		t.Fatal("dated version-bound risk and vendor reviews must be checked", err)
	}
}
