package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/jsii-runtime-go"
)

func TestEdgePrerequisitesHaveOneGlobalWAFAndNoHelpers(t *testing.T) {
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLEDNS")
	t.Setenv("PDF_ALLOWED_CIDR", "203.0.113.10/32")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := edgePrerequisites(app, "111111111111")
	if stack.TerminationProtection() == nil || !*stack.TerminationProtection() {
		t.Fatal("global edge stack lacks termination protection")
	}
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::WAFv2::WebACL"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::WAFv2::IPSet"), jsii.Number(1))
	template.HasResourceProperties(jsii.String("AWS::WAFv2::IPSet"), map[string]any{"Addresses": []string{"203.0.113.10/32"}, "Scope": "CLOUDFRONT"})
	template.ResourceCountIs(jsii.String("AWS::CertificateManager::Certificate"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::IAM::Role"), jsii.Number(0))
	template.HasResourceProperties(jsii.String("AWS::WAFv2::WebACL"), map[string]any{"Scope": "CLOUDFRONT", "Name": "agent-pdf-edge"})
	raw, _ := json.Marshal(*template.ToJSON())
	for _, forbidden := range []string{`"Body"`, `"Captcha"`, `"Challenge"`, `"SampledRequestsEnabled":true`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("agent/upload/privacy-hostile edge config", forbidden)
		}
	}
	if *stack.Region() != "us-east-1" {
		t.Fatal("global WAF/certificate in wrong region")
	}
	resources := (*template.ToJSON())["Resources"].(map[string]interface{})
	for _, raw := range resources {
		r := raw.(map[string]interface{})
		if r["Type"] != "AWS::WAFv2::WebACL" {
			continue
		}
		rules := r["Properties"].(map[string]interface{})["Rules"].([]interface{})
		if len(rules) != 5 {
			t.Fatal("owner gate, geographic policy and three rate rules are required")
		}
		gate := rules[0].(map[string]interface{})
		if gate["Priority"] != float64(0) || gate["Name"] != "TestingOwnerOnly" || gate["Statement"].(map[string]interface{})["NotStatement"] == nil || gate["Action"].(map[string]interface{})["Block"] == nil {
			t.Fatal("non-owner traffic can consume shared rate quota")
		}
		for _, raw := range rules[1:] {
			if raw.(map[string]interface{})["Priority"].(float64) <= 0 {
				t.Fatal("rate evaluated before source-IP block")
			}
			rule := raw.(map[string]interface{})
			if rule["Name"] == "GlobalPdfPostRate" {
				rate := rule["Statement"].(map[string]interface{})["RateBasedStatement"].(map[string]interface{})
				encoded, _ := json.Marshal(rate["ScopeDownStatement"])
				text := string(encoded)
				if rate["Limit"] != float64(120) || rate["AggregateKeyType"] != "CONSTANT" || !strings.Contains(text, `"SearchString":"POST"`) || !strings.Contains(text, `"SearchString":"/v1/pdf/text"`) {
					t.Fatal("global PDF POST backstop changed", rate)
				}
				if strings.Contains(text, "ForwardedIP") || strings.Contains(text, "X-Forwarded-For") {
					t.Fatal("spoofed forwarded IP influences PDF POST backstop")
				}
			}
		}
	}
}

func TestEdgeOriginOnlyAcceptsCloudFrontHTTPSAndSecretHeader(t *testing.T) {
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLEDNS")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("EdgeOriginTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
	albSG, _, _ := networkSecurity(stack, vpc, "203.0.113.10/32", "pl-test")
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc, InternetFacing: jsii.Bool(true), SecurityGroup: albSG})
	t.Setenv("PDF_EDGE_VIEWER_CERT_ARN", "arn:aws:acm:us-east-1:111111111111:certificate/test")
	t.Setenv("PDF_EDGE_WEB_ACL_ARN", "arn:aws:wafv2:us-east-1:111111111111:global/webacl/agent-pdf-edge/test")
	codeFile := filepath.Join(t.TempDir(), "frontdoor.js")
	if err := os.WriteFile(codeFile, []byte("function handler(event) { return event.request; }"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PDF_FRONTDOOR_CODE_FILE", codeFile)
	t.Setenv("PDF_STATIC_INFO_CODE_FILE", codeFile)
	t.Setenv("PDF_STATIC_TERMS_CODE_FILE", codeFile)
	t.Setenv("PDF_STATIC_DISCOVERY_CODE_FILE", codeFile)
	token, cert := edgeOrigin(stack, alb, true)
	listener, conditions := backendListener(alb, true, token, cert)
	listener.AddAction(jsii.String("AllowedOrigin"), &awselasticloadbalancingv2.AddApplicationActionProps{Priority: jsii.Number(10), Conditions: &conditions, Action: awselasticloadbalancingv2.ListenerAction_FixedResponse(jsii.Number(200), nil)})
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::S3::Bucket"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::CloudFront::OriginAccessControl"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::CloudFront::Function"), jsii.Number(4))
	template.HasResourceProperties(jsii.String("AWS::EC2::SecurityGroupIngress"), map[string]any{"SourcePrefixListId": "pl-test", "FromPort": 443, "ToPort": 443})
	template.HasResourceProperties(jsii.String("AWS::ElasticLoadBalancingV2::Listener"), map[string]any{"Port": 443, "Protocol": "HTTPS"})
	root := *template.ToJSON()
	params := root["Parameters"].(map[string]interface{})
	if params["OriginAuthToken"].(map[string]interface{})["NoEcho"] != true {
		t.Fatal("origin token disclosed")
	}
	resources := root["Resources"].(map[string]interface{})
	for _, raw := range resources {
		r := raw.(map[string]interface{})
		p, _ := r["Properties"].(map[string]interface{})
		if r["Type"] == "AWS::CloudFront::Distribution" {
			config := p["DistributionConfig"].(map[string]interface{})
			if config["PriceClass"] != "PriceClass_100" {
				t.Fatal("higher-cost edge price class returned", config["PriceClass"])
			}
			geo := config["Restrictions"].(map[string]interface{})["GeoRestriction"].(map[string]interface{})
			if geo["RestrictionType"] != "blacklist" {
				t.Fatal("CloudFront country block absent")
			}
			actual, _ := json.Marshal(geo["Locations"])
			expected, _ := json.Marshal(cloudFrontBlockedCountries())
			if string(actual) != string(expected) {
				t.Fatal("CloudFront and WAF country policies differ")
			}
			if config["Logging"] != nil {
				t.Fatal("viewer access logging enabled")
			}
			def := config["DefaultCacheBehavior"].(map[string]interface{})
			cacheID, _ := json.Marshal(def["CachePolicyId"])
			if !strings.Contains(string(cacheID), "4135ea2d-6df8-44a3-9df3-4b5a84be39ad") || def["ViewerProtocolPolicy"] != "https-only" {
				t.Fatal("payment caching or HTTP allowed")
			}
			if len(def["FunctionAssociations"].([]interface{})) != 1 {
				t.Fatal("edge admission missing")
			}
			found := map[string]bool{}
			for _, raw := range config["CacheBehaviors"].([]interface{}) {
				behavior := raw.(map[string]interface{})
				route := behavior["PathPattern"].(string)
				if route == "/readme" || route == "/info" || route == "/terms" || route == "/robots.txt" || route == "/sitemap.xml" || route == "/llms.txt" || route == "/.well-known/security.txt" {
					found[route] = true
					if len(behavior["FunctionAssociations"].([]interface{})) != 1 || behavior["ViewerProtocolPolicy"] != "https-only" {
						t.Fatal("static admission missing", route)
					}
					if behavior["TargetOriginId"] != def["TargetOriginId"] {
						t.Fatal("new origin introduced")
					}
					if route != "/readme" {
						associations := behavior["FunctionAssociations"].([]interface{})
						actual, _ := json.Marshal(associations)
						main, _ := json.Marshal(def["FunctionAssociations"])
						if string(actual) == string(main) {
							t.Fatal("policy shares oversized front door", route)
						}
					}
				}
			}
			if len(found) != 7 {
				t.Fatal("static document behavior missing")
			}

			for _, raw := range config["Origins"].([]interface{}) {
				origin := raw.(map[string]interface{})
				if custom, ok := origin["CustomOriginConfig"].(map[string]interface{}); ok {
					if custom["OriginProtocolPolicy"] != "https-only" {
						t.Fatal("ALB origin unencrypted")
					}
				} else if origin["S3OriginConfig"] == nil || origin["OriginAccessControlId"] == nil {
					t.Fatal("static origin lacks authenticated access")
				}
			}
		}
		if r["Type"] == "AWS::EC2::SecurityGroupIngress" && p["CidrIp"] != nil {
			t.Fatal("direct owner/public ALB ingress remains")
		}
	}
	raw, _ := json.Marshal(root)
	if !strings.Contains(string(raw), `"Field":"http-header"`) || !strings.Contains(string(raw), `X-Agent-Pdf-Origin`) {
		t.Fatal("origin header admission absent")
	}
}

func TestPublicCutoverKeepsGeographyRateLimitsAndNoRequestSampling(t *testing.T) {
	t.Setenv("PDF_PUBLIC_ACCESS", "1")
	t.Setenv("PDF_PAYMENT_MODE", "cdp-base")
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLEDNS")
	t.Setenv("PDF_ALLOWED_CIDR", "203.0.113.10/32")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := edgePrerequisites(app, "111111111111")
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::IAM::Role"), jsii.Number(0))
	root := *template.ToJSON()
	found := map[string]bool{}
	for _, raw := range root["Resources"].(map[string]interface{}) {
		r := raw.(map[string]interface{})
		if r["Type"] != "AWS::WAFv2::WebACL" {
			continue
		}
		p := r["Properties"].(map[string]interface{})
		if p["VisibilityConfig"].(map[string]interface{})["SampledRequestsEnabled"] != false {
			t.Fatal("public request sampling")
		}
		for _, raw := range p["Rules"].([]interface{}) {
			rule := raw.(map[string]interface{})
			name := rule["Name"].(string)
			found[name] = true
			if rule["VisibilityConfig"].(map[string]interface{})["SampledRequestsEnabled"] != false {
				t.Fatal("public rule samples requests")
			}
		}
	}
	if found["TestingOwnerOnly"] || !found["GeographicAccessPolicy"] || !found["PerIpRequestRate"] || !found["GlobalRequestRate"] || !found["GlobalPdfPostRate"] || len(found) != 4 {
		t.Fatal("cutover removed traffic safeguards", found)
	}
}
