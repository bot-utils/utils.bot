package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/jsii-runtime-go"
)

func TestHTMLPublicSwitchRequiresExplicitMainnetBrowserLaunch(t *testing.T) {
	t.Setenv("PDF_ENABLE_HTML", "1")
	t.Setenv("PDF_HTML_JAVASCRIPT", "1")
	t.Setenv("PDF_PUBLIC_ACCESS", "1")
	t.Setenv("PDF_PAYMENT_MODE", "cdp-base")
	t.Setenv("PDF_HTML_PUBLIC_ACCESS", "0")
	if htmlPublicAccess() {
		t.Fatal("enabling the service exposed the tool")
	}
	t.Setenv("PDF_HTML_PUBLIC_ACCESS", "1")
	if !htmlPublicAccess() {
		t.Fatal("explicit public cutover ignored")
	}
	for _, key := range []string{"PDF_ENABLE_HTML", "PDF_HTML_JAVASCRIPT", "PDF_PUBLIC_ACCESS", "PDF_PAYMENT_MODE", "PDF_HTML_PUBLIC_ACCESS"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "invalid")
			defer func() {
				if recover() == nil {
					t.Error("unsafe public HTML configuration accepted")
				}
			}()
			htmlPublicAccess()
		})
	}
}

func TestHTMLPublicCutoverKeepsHostMethodsAndRegionalProtection(t *testing.T) {
	for key, value := range map[string]string{"PDF_ENABLE_HTML": "1", "PDF_HTML_JAVASCRIPT": "1", "PDF_HTML_PUBLIC_ACCESS": "1", "PDF_PUBLIC_ACCESS": "1", "PDF_PAYMENT_MODE": "cdp-base", "PDF_ALLOWED_CIDR": "203.0.113.10/32", "PDF_HOSTED_ZONE_ID": "ZEXAMPLE"} {
		t.Setenv(key, value)
	}
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("HtmlPublicCutover"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc, InternetFacing: jsii.Bool(true)})
	origin := alb.AddListener(jsii.String("Origin"), &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(8443), Protocol: awselasticloadbalancingv2.ApplicationProtocol_HTTP, DefaultAction: awselasticloadbalancingv2.ListenerAction_FixedResponse(jsii.Number(404), nil)})
	targets := awselasticloadbalancingv2.NewApplicationTargetGroup(stack, jsii.String("PDF"), &awselasticloadbalancingv2.ApplicationTargetGroupProps{Vpc: vpc, Port: jsii.Number(8080), TargetType: awselasticloadbalancingv2.TargetType_IP})
	controller := awslambda.NewFunction(stack, jsii.String("HTML"), &awslambda.FunctionProps{Runtime: awslambda.Runtime_NODEJS_22_X(), Handler: jsii.String("index.handler"), Code: awslambda.Code_FromInline(jsii.String("exports.handler=async()=>({});"))})
	regionalAPI(stack, alb, targets, origin, controller)
	template := assertions.Template_FromStack(stack, nil)
	found := false
	for _, raw := range (*template.ToJSON())["Resources"].(map[string]any) {
		r := raw.(map[string]any)
		if r["Type"] != "AWS::ElasticLoadBalancingV2::ListenerRule" {
			continue
		}
		encoded, _ := json.Marshal(r["Properties"])
		text := string(encoded)
		if !strings.Contains(text, htmlAPIPath) {
			continue
		}
		found = true
		for _, required := range []string{"host-header", regionalAPIHost, "http-request-method", "POST", "OPTIONS"} {
			if !strings.Contains(text, required) {
				t.Error("public route lost admission condition", required)
			}
		}
		if strings.Contains(text, "source-ip") {
			t.Fatal("public route still restricted to owner")
		}
	}
	if !found {
		t.Fatal("public HTML route absent")
	}
	template.ResourceCountIs(jsii.String("AWS::WAFv2::WebACLAssociation"), jsii.Number(1))
}
