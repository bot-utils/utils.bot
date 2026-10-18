package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
)

func TestBroadGeographicPolicyUsesConnectionIPAndPrecedesRates(t *testing.T) {
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLEDNS")
	t.Setenv("PDF_ALLOWED_CIDR", "203.0.113.10/32")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	template := assertions.Template_FromStack(edgePrerequisites(app, "111111111111"), nil)
	resources := (*template.ToJSON())["Resources"].(map[string]any)
	for _, raw := range resources {
		r := raw.(map[string]any)
		if r["Type"] != "AWS::WAFv2::WebACL" {
			continue
		}
		p := r["Properties"].(map[string]any)
		rule := p["Rules"].([]any)[1].(map[string]any)
		if rule["Name"] != "GeographicAccessPolicy" || rule["Priority"] != float64(1) || rule["Action"].(map[string]any)["Block"] == nil {
			t.Fatal("geographic block missing or evaluated after rate rules")
		}
		geo := rule["Statement"].(map[string]any)["GeoMatchStatement"].(map[string]any)
		if len(geo) != 1 {
			t.Fatal("geography trusts forwarded headers instead of viewer connection")
		}
		actual, _ := json.Marshal(geo["CountryCodes"])
		expected, _ := json.Marshal(blockedCountries())
		if string(actual) != string(expected) || len(blockedCountries()) != 29 {
			t.Fatal("reviewed geographic coverage changed")
		}
		for _, code := range []string{"CN", "HK", "IR", "CU", "KP", "SY", "UA", "RU", "AF", "AL", "BA", "ME", "MK", "RS", "XK"} {
			if !slices.Contains(blockedCountries(), code) {
				t.Fatal("missing reviewed country", code)
			}
		}
		seen := map[string]bool{}
		for _, code := range blockedCountries() {
			if len(code) != 2 || code != strings.ToUpper(code) || seen[code] || code == "US" {
				t.Fatal("invalid country policy", code)
			}
			seen[code] = true
		}
		if rule["VisibilityConfig"].(map[string]any)["SampledRequestsEnabled"] != false {
			t.Fatal("geography retains request samples")
		}
		return
	}
	t.Fatal("global WAF absent")
}

func TestCloudFrontCompatibilityExcludesOnlyWAFProtectedKosovo(t *testing.T) {
	if len(cloudFrontBlockedCountries()) != len(blockedCountries())-1 || slices.Contains(cloudFrontBlockedCountries(), "XK") || !slices.Contains(blockedCountries(), "XK") {
		t.Fatal("invalid CloudFront code or Kosovo geographic protection removed")
	}
	for _, code := range blockedCountries() {
		if code != "XK" && !slices.Contains(cloudFrontBlockedCountries(), code) {
			t.Fatal("supported country missing native CloudFront defense", code)
		}
	}
}
