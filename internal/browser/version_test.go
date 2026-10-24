package browser

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestRuntimeVersionMatchesVerifiedImageAndProvenance(t *testing.T) {
	for _, path := range []string{"../../Dockerfile.browser", "../../native/browser-runtime.py", "../../scripts/check_html_image.py", "../../scripts/html_risk_review.py"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), Version) {
			t.Fatalf("browser runtime/provenance drift in %s", path)
		}
	}
	b, err := os.ReadFile("../../Dockerfile.browser")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"FROM scratch AS browser-base", "ADD --checksum=sha256:", "USER 10001:10001", "COPY --from=browser-dependencies /runtime/ /"} {
		if !strings.Contains(string(b), required) {
			t.Fatal("browser image lost security invariant", required)
		}
	}
	archive := regexp.MustCompile(`ADD --checksum=sha256:([a-f0-9]{64}) https://storage.googleapis.com/chrome-for-testing-public/([^/]+)/linux-arm64/chrome-headless-shell-linux-arm64.zip`).FindStringSubmatch(string(b))
	if len(archive) != 3 || archive[2] != Version {
		t.Fatal("browser archive is not the expected pinned ARM64 release")
	}
	check, err := os.ReadFile("../../scripts/check_html_image.py")
	if err != nil || !strings.Contains(string(check), archive[1]) {
		t.Fatal("archive checksum and filesystem provenance check differ", err)
	}
}
