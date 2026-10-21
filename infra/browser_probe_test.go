package main

import (
	"encoding/json"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserProbeHasNoIngressOrApplicationAuthority(t *testing.T) {
	t.Setenv("PDF_USE_DEDICATED_EXECUTION_ROLE", "1")
	defer jsii.Close()
	temp := t.TempDir()
	infra := filepath.Join(temp, "infra")
	os.MkdirAll(infra, 0700)
	for _, name := range []string{"native/browser-launch.c", "build/browser-probe/bootstrap", "Dockerfile.browser", "Dockerfile.browser.dockerignore"} {
		p := filepath.Join(temp, name)
		os.MkdirAll(filepath.Dir(p), 0700)
		os.WriteFile(p, []byte("synthesis fixture"), 0600)
	}
	cwd, _ := os.Getwd()
	os.Chdir(infra)
	defer os.Chdir(cwd)
	app := awscdk.NewApp(nil)
	stack := browserProbeStack(app, "111111111111", "us-east-2")
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(1))
	for _, typ := range []string{"AWS::Lambda::Url", "AWS::Lambda::Permission", "AWS::ElasticLoadBalancingV2::ListenerRule", "AWS::Events::Rule", "AWS::S3::Bucket"} {
		template.ResourceCountIs(jsii.String(typ), jsii.Number(0))
	}
	template.HasResourceProperties(jsii.String("AWS::Lambda::Function"), map[string]any{"FunctionName": "agent-pdf-html-browser-probe", "PackageType": "Image", "MemorySize": 2048, "ReservedConcurrentExecutions": 2, "TenancyConfig": map[string]any{"TenantIsolationMode": "PER_TENANT"}})
	resources := (*template.ToJSON())["Resources"].(map[string]any)
	for _, raw := range resources {
		r := raw.(map[string]any)
		if r["Type"] == "AWS::IAM::Policy" {
			b, _ := json.Marshal(r)
			for _, bad := range []string{"ssm:", "dynamodb:", "s3:", "lambda:InvokeFunction", "secretsmanager:"} {
				if strings.Contains(string(b), bad) {
					t.Fatal("probe privilege", bad)
				}
			}
		}
	}
}

func TestBrowserProbeRefusesUnboundedDeployment(t *testing.T) {
	t.Setenv("PDF_USE_DEDICATED_EXECUTION_ROLE", "0")
	defer func() {
		if recover() == nil {
			t.Fatal("unbounded probe deployment accepted")
		}
	}()
	browserProbeStack(nil, "111111111111", "us-east-2")
}
