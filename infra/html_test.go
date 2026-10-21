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
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/jsii-runtime-go"
)

func TestHTMLDraftIAMIsolationAndDirectPrivateIngress(t *testing.T) {
	t.Setenv("PDF_ENABLE_HTML", "1")
	t.Setenv("PDF_USE_DEDICATED_EXECUTION_ROLE", "1")
	t.Setenv("PDF_DIRECT_API", "1")
	t.Setenv("PDF_PUBLIC_ACCESS", "1")
	t.Setenv("PDF_ALLOWED_CIDR", "203.0.113.10/32")
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLE")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("HtmlTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
	applyRuntimeBoundary(stack, "111111111111", false)
	payment := awslambda.NewFunction(stack, jsii.String("Payment"), &awslambda.FunctionProps{Runtime: awslambda.Runtime_NODEJS_22_X(), Handler: jsii.String("index.handler"), Code: awslambda.Code_FromInline(jsii.String("exports.handler=async()=>({});"))})
	alias := awslambda.NewAlias(stack, jsii.String("PayAlias"), &awslambda.AliasProps{AliasName: jsii.String("live"), Version: payment.CurrentVersion()})
	// Functions need existing build assets at synth time; keep tests self-contained
	// by supplying inert files in a temporary working directory.
	temp := t.TempDir()
	infraDir := filepath.Join(temp, "infra")
	if err := os.MkdirAll(infraDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"html", "html-worker", "threat-update"} {
		dir := filepath.Join(temp, "build", name)
		os.MkdirAll(dir, 0700)
		if err := os.WriteFile(filepath.Join(dir, "bootstrap"), []byte("not executable; synthesis test only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cwd, _ := os.Getwd()
	if err := os.Chdir(infraDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	controller := htmlFunctions(stack, alias, paymentConfig{Mode: "mock", PayTo: "0x1111111111111111111111111111111111111111"})
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc, InternetFacing: jsii.Bool(true)})
	origin := alb.AddListener(jsii.String("Origin"), &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(8443), Protocol: awselasticloadbalancingv2.ApplicationProtocol_HTTP, DefaultAction: awselasticloadbalancingv2.ListenerAction_FixedResponse(jsii.Number(404), nil)})
	targets := awselasticloadbalancingv2.NewApplicationTargetGroup(stack, jsii.String("PdfTargets"), &awselasticloadbalancingv2.ApplicationTargetGroupProps{Vpc: vpc, Port: jsii.Number(8080), TargetType: awselasticloadbalancingv2.TargetType_IP})
	regionalAPI(stack, alb, targets, origin, controller)
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(4))
	template.ResourceCountIs(jsii.String("AWS::S3::Bucket"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::Events::Rule"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::Lambda::Url"), jsii.Number(0))
	resources := (*template.ToJSON())["Resources"].(map[string]any)
	roles := map[string]string{}
	policies := map[string]string{}
	for _, raw := range resources {
		r := raw.(map[string]any)
		p, _ := r["Properties"].(map[string]any)
		switch r["Type"] {
		case "AWS::Lambda::Function":
			name, _ := p["FunctionName"].(string)
			if !strings.HasPrefix(name, "agent-pdf-html") {
				continue
			}
			role := p["Role"].(map[string]any)["Fn::GetAtt"].([]any)[0].(string)
			roles[name] = role
			if p["VpcConfig"] != nil || p["FileSystemConfigs"] != nil {
				t.Fatal("unneeded network/filesystem authority")
			}
			if name == "agent-pdf-html-worker" {
				if p["MemorySize"] != float64(256) {
					t.Fatal("worker still sized for a full per-job threat list")
				}
				if p["TenancyConfig"].(map[string]any)["TenantIsolationMode"] != "PER_TENANT" {
					t.Fatal("worker isolation missing")
				}
				env := p["Environment"].(map[string]any)["Variables"].(map[string]any)
				for k := range env {
					if k != "THREAT_BUCKET" && k != "GOMEMLIMIT" {
						t.Fatal("worker exposed configuration", k)
					}
				}
			}
		case "AWS::IAM::Policy":
			b, _ := json.Marshal(p["PolicyDocument"])
			for _, role := range p["Roles"].([]any) {
				if ref, ok := role.(map[string]any)["Ref"].(string); ok {
					policies[ref] += string(b)
				}
			}
		case "AWS::S3::Bucket":
			rules := p["LifecycleConfiguration"].(map[string]any)["Rules"].([]any)
			if len(rules) != 1 || rules[0].(map[string]any)["ExpirationInDays"] != float64(3) || rules[0].(map[string]any)["Prefix"] != "threats/v2/generations/" {
				t.Fatal("old threat generations have no bounded retention")
			}
			block := p["PublicAccessBlockConfiguration"].(map[string]any)
			for _, v := range block {
				if v != true {
					t.Fatal("public threat bucket")
				}
			}
			if p["WebsiteConfiguration"] != nil || p["LoggingConfiguration"] != nil {
				t.Fatal("bucket exposure/logging")
			}
		case "AWS::ElasticLoadBalancingV2::TargetGroup":
			if p["TargetType"] == "lambda" {
				b, _ := json.Marshal(p)
				if !strings.Contains(string(b), "lambda.multi_value_headers.enabled") || p["HealthCheckEnabled"] != false {
					t.Fatal("ALB lambda envelope/health unsafe")
				}
			}
		case "AWS::ElasticLoadBalancingV2::ListenerRule":
			b, _ := json.Marshal(p)
			if strings.Contains(string(b), htmlAPIPath) && (!strings.Contains(string(b), "203.0.113.10/32") || !strings.Contains(string(b), "source-ip")) {
				t.Fatal("draft is publicly routed")
			}
		case "AWS::Lambda::Permission":
			if p["Principal"] == "elasticloadbalancing.amazonaws.com" {
				b, _ := json.Marshal(p["SourceArn"])
				if !strings.Contains(string(b), "targetgroup/agent-pdf-mock-html/*") || p["SourceAccount"] != "111111111111" {
					t.Fatal("unscoped ALB invoke", p)
				}
			}
		case "AWS::Events::Rule":
			if p["ScheduleExpression"] != "rate(1 hour)" {
				t.Fatal("refresh not scheduled")
			}
		}
	}
	for name, role := range roles {
		p := resources[role].(map[string]any)["Properties"].(map[string]any)
		if p["ManagedPolicyArns"] != nil || p["PermissionsBoundary"] != "arn:aws:iam::111111111111:policy/"+runtimeBoundaryName {
			t.Fatal("HTML role lacks a bounded, explicit policy", name, p)
		}
		text := policies[role]
		switch name {
		case "agent-pdf-html-worker":
			if !strings.Contains(text, "s3:GetObject") || strings.Contains(text, "s3:PutObject") {
				t.Fatal("worker bucket authority", text)
			}
		case "agent-pdf-html-threat-update":
			if !strings.Contains(text, "s3:PutObject") || strings.Contains(text, "s3:GetObject") {
				t.Fatal("updater bucket authority", text)
			}
		case "agent-pdf-html":
			if !strings.Contains(text, "lambda:InvokeFunction") || strings.Contains(text, "s3:") {
				t.Fatal("controller authority", text)
			}
		}
		if strings.Contains(text, "ssm:") || strings.Contains(text, "dynamodb:") {
			t.Fatal("HTML role can access payment data", name, text)
		}
	}
}

func TestHTMLBrowserImageRemainsOptInIsolatedAndBounded(t *testing.T) {
	t.Setenv("PDF_ENABLE_HTML", "1")
	t.Setenv("PDF_MICROVM_BASE_VERSION", "1.0")
	t.Setenv("PDF_HTML_JAVASCRIPT", "1")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("HtmlBrowserTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
	payment := awslambda.NewFunction(stack, jsii.String("Payment"), &awslambda.FunctionProps{Runtime: awslambda.Runtime_NODEJS_22_X(), Handler: jsii.String("index.handler"), Code: awslambda.Code_FromInline(jsii.String("exports.handler=async()=>({});"))})
	alias := awslambda.NewAlias(stack, jsii.String("PayAlias"), &awslambda.AliasProps{AliasName: jsii.String("live"), Version: payment.CurrentVersion()})
	temp := t.TempDir()
	infraDir := filepath.Join(temp, "infra")
	os.MkdirAll(infraDir, 0700)
	for _, name := range []string{"html", "html-worker", "threat-update"} {
		dir := filepath.Join(temp, "build", name)
		os.MkdirAll(dir, 0700)
		os.WriteFile(filepath.Join(dir, "bootstrap"), []byte("synthesis only"), 0600)
	}
	os.MkdirAll(filepath.Join(temp, "build/html-microvm-image/native"), 0700)
	for _, f := range []string{"Dockerfile", "runtime.tar"} {
		os.WriteFile(filepath.Join(temp, "build/html-microvm-image", f), []byte("synthesis only"), 0600)
	}
	cwd, _ := os.Getwd()
	os.Chdir(infraDir)
	defer os.Chdir(cwd)
	htmlFunctions(stack, alias, paymentConfig{Mode: "mock", PayTo: "0x1111111111111111111111111111111111111111"})
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::Lambda::MicrovmImage"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(3))
	template.HasResourceProperties(jsii.String("AWS::Lambda::MicrovmImage"), map[string]any{"Name": "agent-pdf-html-browser", "AdditionalOsCapabilities": []any{}, "BaseImageVersion": "1.0", "Resources": []any{map[string]any{"MinimumMemoryInMiB": 512}}})

	template.HasResourceProperties(jsii.String("AWS::Lambda::Function"), map[string]any{"FunctionName": "agent-pdf-html", "Environment": map[string]any{"Variables": map[string]any{"HTML_JAVASCRIPT": "1"}}})
}
