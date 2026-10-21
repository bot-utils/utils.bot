package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
)

// Unreviewed native findings block public HTML deployment. Explicit accepted
// risks remain unpatched and require a separate expiring confinement review.
// Private integration
// probes return before this check in main; they never advertise the tool or use
// the production payment table. Isolation alone does not mark a CVE patched.
// The frozen-runtime artifact check is also required: policy review alone
// cannot certify the filesystem handed to AWS.
func requireHTMLNativeReview(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("HTML native review policy missing")
	}
	var policy struct {
		Findings []struct {
			Package   string   `json:"package"`
			CVE       string   `json:"cve"`
			Status    string   `json:"status"`
			Version   string   `json:"version"`
			Forbidden []string `json:"forbidden"`
		} `json:"findings"`
	}
	if json.Unmarshal(data, &policy) != nil || len(policy.Findings) == 0 {
		return errors.New("HTML native review policy invalid")
	}
	seen := make(map[string]bool)
	vendorReview := false
	riskReview := false
	for _, finding := range policy.Findings {
		key := finding.Package + ":" + finding.CVE
		if finding.Package == "" || finding.CVE == "" || seen[key] {
			return errors.New("HTML native review identity missing or duplicated")
		}
		seen[key] = true
		switch finding.Status {
		case "fixed":
			if finding.Version == "" {
				return errors.New("HTML native review lacks fixed version")
			}
		case "vendor_disputed":
			if finding.Version == "" {
				return errors.New("HTML vendor review lacks exact version")
			}
			vendorReview = true
		case "risk_accepted":
			if finding.Version == "" {
				return errors.New("HTML risk acceptance lacks exact version")
			}
			riskReview = true
		case "component_absent":
			if finding.Version == "" || len(finding.Forbidden) == 0 {
				return errors.New("HTML absent-component review lacks version or component")
			}
			for _, component := range finding.Forbidden {
				if component == "" {
					return errors.New("HTML absent-component review has empty component")
				}
			}
		default:
			return errors.New("HTML release blocked by unresolved native advisories; private tests remain available")
		}
	}
	if vendorReview {
		if exec.Command("python3", "../scripts/check_html_vendor_reviews.py", path).Run() != nil {
			return errors.New("HTML vendor classification review missing, changed or expired")
		}
	}
	if riskReview {
		if exec.Command("python3", "../scripts/check_html_risk_reviews.py", path).Run() != nil {
			return errors.New("HTML risk acceptance missing, changed or expired")
		}
	}
	return nil
}

func requireHTMLRuntimeArtifact() error {
	command := exec.Command("python3", "../scripts/check_html_release.py", "../build/html-microvm-image")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		return errors.New("HTML frozen runtime release validation failed")
	}
	return nil
}
