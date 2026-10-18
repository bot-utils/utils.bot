package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAssociationLookupPermissionHasRequiredReadScope(t *testing.T) {
	raw, err := os.ReadFile("pdf-guardrail-permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Statement []struct {
			Effect    string
			Action    any
			Resource  any
			Condition map[string]any
		}
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	lookup := false
	for _, statement := range policy.Statement {
		if statement.Effect != "Allow" {
			t.Fatal("unexpected permission effect")
		}
		if statement.Resource == "arn:aws:wafv2:us-east-2:${AWS_ACCOUNT_ID}:regional/webacl/*/*" {
			if statement.Action != "wafv2:GetWebACLForResource" {
				t.Fatal("broader WAF scope permits writes")
			}
			lookup = true
		}
		if statement.Resource == "*" {
			want := map[string]any{"StringEquals": map[string]any{"aws:RequestedRegion": "us-east-2"}}
			if statement.Action != "elasticloadbalancing:SetWebAcl" || !reflect.DeepEqual(statement.Condition, want) {
				t.Fatal("wildcard permission widened")
			}
		}
	}
	if !lookup {
		t.Fatal("ALB association lookup cannot discover the existing regional ACL")
	}
}

func TestEdgePolicyCanMaintainEveryOwnedCloudFrontFunction(t *testing.T) {
	raw, err := os.ReadFile("pdf-edge-permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Statement []struct {
			Action   any
			Resource any
		}
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	want := "arn:aws:cloudfront::${AWS_ACCOUNT_ID}:function/agent-pdf-*"
	found := false
	for _, statement := range policy.Statement {
		actions, ok := statement.Action.([]any)
		if !ok {
			continue
		}
		maintainsFunctions := false
		for _, action := range actions {
			if action == "cloudfront:UpdateFunction" || action == "cloudfront:PublishFunction" || action == "cloudfront:DeleteFunction" {
				maintainsFunctions = true
			}
		}
		if !maintainsFunctions {
			continue
		}
		resources, ok := statement.Resource.([]any)
		if !ok {
			t.Fatal("CloudFront maintenance resources must remain explicit")
		}
		for _, resource := range resources {
			value := resource.(string)
			if value == want {
				found = true
			}
			if strings.Contains(value, ":function/") && value != want {
				t.Fatal("CloudFront function maintenance scope is incomplete or widened", value)
			}
		}
	}
	if !found {
		t.Fatal("static info, terms and discovery functions cannot be updated by the deployment role")
	}
}

// The operator-specific migration policy is excluded from this source snapshot.
func TestTemporaryControlPlanePermissionIsNarrowAndRemovable(t *testing.T) {
	t.Skip("operator-specific migration policy omitted from publication snapshot")
}

func TestRegionalAPIPermissionOnlyAddsCanonicalDomain(t *testing.T) {
	raw, err := os.ReadFile("pdf-edge-permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Statement []struct {
			Action    any
			Condition map[string]any
		}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, s := range p.Statement {
		if s.Action == "acm:RequestCertificate" {
			names := s.Condition["ForAllValues:StringEquals"].(map[string]any)["acm:DomainNames"]
			if !reflect.DeepEqual(names, []any{"utils.bot", "origin.utils.bot", "api.utils.bot"}) {
				t.Fatal("certificate scope widened", names)
			}
			found++
		}
		if s.Action == "route53:ChangeResourceRecordSets" {
			names := s.Condition["ForAllValues:StringLike"].(map[string]any)["route53:ChangeResourceRecordSetsNormalizedRecordNames"]
			if !reflect.DeepEqual(names, []any{"utils.bot", "origin.utils.bot", "_*.utils.bot", "api.utils.bot"}) {
				t.Fatal("DNS scope widened", names)
			}
			found++
		}
	}
	if found != 2 {
		t.Fatal("scoped API DNS/TLS permissions missing")
	}
}

func TestStaticPublisherAndManagementAreSeparateAndBucketScoped(t *testing.T) {
	for _, name := range []string{"pdf-static-site-permissions.json", "pdf-static-site-upload-permissions.json"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var p struct {
			Statement []struct {
				Action    any
				Resource  string
				Condition map[string]any
			}
		}
		if err = json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if len(p.Statement) != 1 {
			t.Fatal("unexpected static grants")
		}
		s := p.Statement[0]
		bucket := "arn:aws:s3:::${STATIC_SITE_BUCKET}"
		if name == "pdf-static-site-upload-permissions.json" {
			if s.Action != "s3:PutObject" || s.Resource != bucket+"/public/*" || s.Condition["StringEquals"].(map[string]any)["s3:x-amz-server-side-encryption"] != "AES256" {
				t.Fatal("publisher scope expanded", s)
			}
		} else {
			if s.Resource != bucket {
				t.Fatal("management can affect other buckets/objects")
			}
			metadataReads := map[string]bool{}
			for _, action := range s.Action.([]any) {
				metadataReads[action.(string)] = true
				if strings.Contains(action.(string), "*") || action == "s3:PutObject" || action == "s3:DeleteObject" || action == "s3:DeleteBucket" {
					t.Fatal("management includes unnecessary data/deletion authority", action)
				}
			}
			for _, action := range []string{"s3:GetBucketLogging", "s3:GetBucketNotification", "s3:GetLifecycleConfiguration", "s3:ListBucket"} {
				if !metadataReads[action] {
					t.Fatal("CloudFormation cannot stabilize/read static bucket metadata", action)
				}
			}
		}
	}
}
