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

func TestDirectAPIUsesSeparatePrivatePortAndRegionalControls(t *testing.T) {
	for _, public := range []string{"0", "1"} {
		t.Run("public-"+public, func(t *testing.T) {
			t.Setenv("PDF_DIRECT_API", "1")
			t.Setenv("PDF_PUBLIC_ACCESS", public)
			t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLEDNS")
			t.Setenv("PDF_EDGE_VIEWER_CERT_ARN", "arn:aws:acm:us-east-1:111111111111:certificate/test")
			t.Setenv("PDF_EDGE_WEB_ACL_ARN", "arn:aws:wafv2:us-east-1:111111111111:global/webacl/agent-pdf-edge/test")
			file := filepath.Join(t.TempDir(), "code.js")
			if err := os.WriteFile(file, []byte("function handler(e){return e.request;}"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"PDF_FRONTDOOR_CODE_FILE", "PDF_STATIC_INFO_CODE_FILE", "PDF_STATIC_TERMS_CODE_FILE", "PDF_STATIC_DISCOVERY_CODE_FILE"} {
				t.Setenv(key, file)
			}
			defer jsii.Close()
			app := awscdk.NewApp(nil)
			stack := awscdk.NewStack(app, jsii.String("RegionalTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
			vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
			sg, _, originSG := networkSecurity(stack, vpc, "203.0.113.10/32", "pl-test")
			alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc, SecurityGroup: sg, InternetFacing: jsii.Bool(true)})
			if originSG == nil {
				t.Fatal("regional migration must isolate the weighted CloudFront prefix rule")
			}
			alb.AddSecurityGroup(originSG)
			targets := awselasticloadbalancingv2.NewApplicationTargetGroup(stack, jsii.String("Targets"), &awselasticloadbalancingv2.ApplicationTargetGroupProps{Vpc: vpc, Port: jsii.Number(8080), TargetType: awselasticloadbalancingv2.TargetType_IP})
			token, cert := edgeOrigin(stack, alb, true)
			origin, conditions := backendListener(alb, true, token, cert)
			origin.AddAction(jsii.String("OriginTarget"), &awselasticloadbalancingv2.AddApplicationActionProps{Priority: jsii.Number(10), Conditions: &conditions, Action: awselasticloadbalancingv2.ListenerAction_Forward(&[]awselasticloadbalancingv2.IApplicationTargetGroup{targets}, nil)})
			regionalAPI(stack, alb, targets, origin)
			template := assertions.Template_FromStack(stack, nil)
			for kind, count := range map[string]int{"AWS::ElasticLoadBalancingV2::LoadBalancer": 1, "AWS::ElasticLoadBalancingV2::Listener": 2, "AWS::ElasticLoadBalancingV2::TargetGroup": 1, "AWS::WAFv2::WebACL": 1, "AWS::WAFv2::WebACLAssociation": 1, "AWS::Lambda::Function": 0, "AWS::S3::Bucket": 0} {
				template.ResourceCountIs(jsii.String(kind), jsii.Number(float64(count)))
			}
			cidr := "203.0.113.10/32"
			if public == "1" {
				cidr = "0.0.0.0/0"
			}
			template.HasResourceProperties(jsii.String("AWS::EC2::SecurityGroupIngress"), map[string]any{"SourcePrefixListId": "pl-test", "FromPort": 8443, "ToPort": 8443})
			template.HasResourceProperties(jsii.String("AWS::EC2::SecurityGroupIngress"), map[string]any{"CidrIp": cidr, "FromPort": 443, "ToPort": 443})
			template.HasResourceProperties(jsii.String("AWS::CertificateManager::Certificate"), map[string]any{"DomainName": regionalAPIHost, "ValidationMethod": "DNS"})
			template.HasResourceProperties(jsii.String("AWS::Route53::RecordSet"), map[string]any{"Name": regionalAPIHost, "Type": "A"})
			var prefixGroup, apiGroup string
			for _, raw := range (*template.ToJSON())["Resources"].(map[string]any) {
				r := raw.(map[string]any)
				p, _ := r["Properties"].(map[string]any)
				switch r["Type"] {
				case "AWS::EC2::SecurityGroupIngress":
					group, _ := json.Marshal(p["GroupId"])
					if p["SourcePrefixListId"] == "pl-test" {
						prefixGroup = string(group)
					}
					if p["CidrIp"] == cidr {
						apiGroup = string(group)
					}
					if p["FromPort"] == float64(8443) && (p["SourcePrefixListId"] != "pl-test" || p["CidrIp"] != nil) {
						t.Fatal("origin network exposed", p)
					}
					if p["CidrIp"] != nil && (p["CidrIp"] != cidr || p["FromPort"] != float64(443)) {
						t.Fatal("unexpected direct ingress", p)
					}
				case "AWS::ElasticLoadBalancingV2::Listener":
					if p["Port"] == float64(443) && (p["Protocol"] != "HTTPS" || p["SslPolicy"] != "ELBSecurityPolicy-TLS13-1-2-Res-2021-06" || p["DefaultActions"].([]any)[0].(map[string]any)["Type"] != "fixed-response") {
						t.Fatal("direct listener defaults unsafe", p)
					}
					if p["Port"] == float64(443) {
						depends, _ := r["DependsOn"].([]any)
						originID := *stack.GetLogicalId(origin.Node().DefaultChild().(awscdk.CfnElement))
						found := false
						for _, dependency := range depends {
							found = found || dependency == originID
						}
						if !found {
							t.Fatal("API listener can race the legacy origin for port 443")
						}
					}
				case "AWS::ElasticLoadBalancingV2::ListenerRule":
					b, _ := json.Marshal(p["Conditions"])
					text := string(b)
					if strings.Contains(text, regionalAPIHost) && (!strings.Contains(text, "POST") || !strings.Contains(text, "OPTIONS") || !strings.Contains(text, "/v1/pdf/text")) {
						t.Fatal("API route widened", text)
					}
				case "AWS::CloudFront::Distribution":
					for _, origin := range p["DistributionConfig"].(map[string]any)["Origins"].([]any) {
						o := origin.(map[string]any)
						custom := o["CustomOriginConfig"].(map[string]any)
						if custom["HTTPSPort"] != float64(8443) || custom["OriginProtocolPolicy"] != "https-only" || o["OriginCustomHeaders"] == nil {
							t.Fatal("website origin protection changed", o)
						}
					}
				case "AWS::WAFv2::WebACL":
					if p["Scope"] != "REGIONAL" {
						t.Fatal("wrong WAF scope")
					}
					rules := p["Rules"].([]any)
					if len(rules) != 6 {
						t.Fatal("pricing/rule count drift", len(rules))
					}
					for _, raw := range rules {
						rule := raw.(map[string]any)
						if rule["Name"] == "ApiContentHeaders" {
							conditions := rule["Statement"].(map[string]any)["AndStatement"].(map[string]any)["Statements"].([]any)
							if len(conditions) != 5 {
								t.Fatal("content prefilter lost its API host/path/method/payment conditions")
							}
							for _, condition := range conditions {
								if condition.(map[string]any)["AndStatement"] != nil {
									t.Fatal("AWS rejects the directly nested AND content prefilter")
								}
							}
						}
						b, _ := json.Marshal(rule)
						text := string(b)
						if strings.Contains(text, `"SingleHeader":{"name"`) {
							t.Fatal("WAF SingleHeader must use CloudFormation Name property", text)
						}
						if !strings.Contains(text, regionalAPIHost) || strings.Contains(text, "ForwardedIP") || strings.Contains(text, `"Body"`) || rule["VisibilityConfig"].(map[string]any)["SampledRequestsEnabled"] != false {
							t.Fatal("unsafe scope/logging", text)
						}
						if rate, ok := rule["Statement"].(map[string]any)["RateBasedStatement"].(map[string]any); ok {
							want := map[string]float64{"PerIpRequestRate": 300, "GlobalRequestRate": 1000, "GlobalPdfPostRate": 120}[rule["Name"].(string)]
							if rate["Limit"] != want || rate["EvaluationWindowSec"] != float64(60) {
								t.Fatal("quota drift", rate)
							}
							key := "CONSTANT"
							if rule["Name"] == "PerIpRequestRate" {
								key = "IP"
							}
							if rate["AggregateKeyType"] != key {
								t.Fatal("spoofable rate key", rate)
							}
						}
					}
				}
			}
			if prefixGroup == "" || apiGroup == "" || prefixGroup == apiGroup {
				t.Fatal("CloudFront origin rule shares the API group and can exhaust its migration rule quota")
			}
			template.HasResourceProperties(jsii.String("AWS::ElasticLoadBalancingV2::LoadBalancer"), map[string]any{"SecurityGroups": []any{map[string]any{"Fn::GetAtt": []any{*stack.GetLogicalId(sg.Node().DefaultChild().(awscdk.CfnElement)), "GroupId"}}, map[string]any{"Fn::GetAtt": []any{*stack.GetLogicalId(originSG.Node().DefaultChild().(awscdk.CfnElement)), "GroupId"}}}})
		})
	}
}
func TestDirectAPIFlagFailsClosed(t *testing.T) {
	t.Setenv("PDF_DIRECT_API", "invalid")
	defer func() {
		if recover() == nil {
			t.Fatal("invalid feature setting accepted")
		}
	}()
	directAPIEnabled()
}
