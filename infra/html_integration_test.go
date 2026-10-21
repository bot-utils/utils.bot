package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
)

func TestHTMLIntegrationCannotUseRealPaymentsOrAlterLiveCompute(t *testing.T) {
	t.Setenv("PDF_ENABLE_HTML", "1")
	t.Setenv("PDF_HTML_REUSE_THREATS", "1")
	t.Setenv("PDF_HTML_JAVASCRIPT", "1")
	t.Setenv("PDF_USE_DEDICATED_EXECUTION_ROLE", "1")
	t.Setenv("PDF_MICROVM_BASE_VERSION", "2")
	t.Setenv("PDF_ALLOWED_CIDR", "203.0.113.10/32")
	t.Setenv("PDF_HTML_TEST_LISTENER_ARN", "arn:aws:elasticloadbalancing:us-east-2:111111111111:listener/app/agent-pdf-mock/aaaaaaaa/bbbbbbbb")
	// Deliberately inherit hostile production settings: this stack ignores them.
	t.Setenv("PDF_PAYMENT_MODE", "cdp-base")
	t.Setenv("PDF_PAYMENT_PAY_TO", "0x2222222222222222222222222222222222222222")
	root := t.TempDir()
	dir := filepath.Join(root, "infra")
	os.MkdirAll(dir, 0700)
	t.Chdir(dir)
	for _, file := range []string{"payment/bootstrap", "html-network-check/bootstrap", "html/bootstrap", "threat-update/bootstrap", "html-microvm-image/runtime.tar", "html-microvm-image/Dockerfile", "html-microvm-image/native/browser-launch.c"} {
		p := filepath.Join(root, "build", file)
		os.MkdirAll(filepath.Dir(p), 0700)
		if err := os.WriteFile(p, []byte("synthesis only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := htmlIntegrationStack(app, "111111111111", "us-east-2")
	template := assertions.Template_FromStack(stack, nil)
	for _, kind := range []string{"AWS::ECS::Service", "AWS::ECS::TaskDefinition", "AWS::ElasticLoadBalancingV2::Listener", "AWS::WAFv2::WebACL", "AWS::Route53::RecordSet", "AWS::Lambda::Url"} {
		template.ResourceCountIs(jsii.String(kind), jsii.Number(0))
	}
	template.ResourceCountIs(jsii.String("AWS::S3::Bucket"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::S3::BucketPolicy"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::DynamoDB::Table"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(4))
	template.HasResourceProperties(jsii.String("AWS::DynamoDB::Table"), map[string]any{"TableName": "agent-pdf-html-test-payments", "TimeToLiveSpecification": map[string]any{"AttributeName": "expiresAt", "Enabled": true}})
	template.HasResourceProperties(jsii.String("AWS::Lambda::Function"), map[string]any{"FunctionName": "agent-pdf-html-test-payment", "Environment": map[string]any{"Variables": map[string]any{"PAYMENT_MODE": "mock", "PAYMENT_PAY_TO": "0x1111111111111111111111111111111111111111"}}})
	resources := (*template.ToJSON())["Resources"].(map[string]any)
	for _, raw := range resources {
		r := raw.(map[string]any)
		b, _ := json.Marshal(r)
		s := string(b)
		if strings.Contains(s, "ssm:Get") || strings.Contains(s, "agent-pdf-mock-payment:live") || strings.Contains(s, "agent-pdf-mock-payments") {
			t.Fatal("test stack can access live payment authority", s)
		}
		if r["Type"] == "AWS::S3::BucketPolicy" && (r["DeletionPolicy"] != "Retain" || !strings.Contains(s, "aws:SecureTransport")) {
			t.Fatal("retained threat cache loses TLS-only policy", s)
		}
		if r["Type"] == "AWS::ElasticLoadBalancingV2::ListenerRule" && (!strings.Contains(s, "203.0.113.10/32") || !strings.Contains(s, "source-ip") || !strings.Contains(s, "HttpRequestMethodConfig") || !strings.Contains(s, "SourceIpConfig") || !strings.Contains(s, htmlAPIPath)) {
			t.Fatal("draft route not owner restricted", s)
		}
		if r["Type"] == "AWS::Lambda::Permission" && (!strings.Contains(s, "targetgroup/agent-pdf-mock-html-test/*") && strings.Contains(s, "elasticloadbalancing.amazonaws.com")) {
			t.Fatal("unscoped ALB permission", s)
		}
	}
}
