package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

func TestMicroVMProbeBuildPermissionsAndNoRuntimeRole(t *testing.T) {
	t.Setenv("PDF_USE_DEDICATED_EXECUTION_ROLE", "1")
	t.Setenv("PDF_MICROVM_BASE_VERSION", "2")
	defer jsii.Close()
	temp := t.TempDir()
	os.MkdirAll(filepath.Join(temp, "infra"), 0700)
	os.MkdirAll(filepath.Join(temp, "build/html-microvm-image/native"), 0700)
	for _, name := range []string{"Dockerfile", "runtime.tar"} {
		os.WriteFile(filepath.Join(temp, "build/html-microvm-image", name), []byte("synthesis only"), 0600)
	}
	cwd, _ := os.Getwd()
	os.Chdir(filepath.Join(temp, "infra"))
	defer os.Chdir(cwd)
	stack := microVMProbeStack(awscdk.NewApp(nil), "111111111111", "us-east-2")
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::Lambda::MicrovmImage"), jsii.Number(1))
	for _, typ := range []string{"AWS::Lambda::Function", "AWS::Lambda::Url", "AWS::ElasticLoadBalancingV2::ListenerRule", "AWS::Events::Rule", "AWS::S3::Bucket"} {
		template.ResourceCountIs(jsii.String(typ), jsii.Number(0))
	}
	template.ResourceCountIs(jsii.String("AWS::IAM::Role"), jsii.Number(1))
	template.HasResourceProperties(jsii.String("AWS::Lambda::MicrovmImage"), map[string]any{"Tags": []any{map[string]any{"Key": "Project", "Value": "agent-pdf"}}})
	template.HasResourceProperties(jsii.String("AWS::Logs::LogGroup"), map[string]any{"RetentionInDays": 7})
	template.HasResourceProperties(jsii.String("AWS::IAM::Role"), map[string]any{"PermissionsBoundary": "arn:aws:iam::111111111111:policy/" + runtimeBoundaryName})
	resources := (*template.ToJSON())["Resources"].(map[string]any)
	for _, raw := range resources {
		r := raw.(map[string]any)
		p := r["Properties"].(map[string]any)
		if r["Type"] == "AWS::IAM::Policy" {
			b, _ := json.Marshal(p)
			text := string(b)
			for _, bad := range []string{"ssm:", "dynamodb:", "secretsmanager:", "s3:PutObject", "lambda:InvokeFunction", "lambda:RunMicrovm"} {
				if strings.Contains(text, bad) {
					t.Fatal("build privilege", bad)
				}
			}
			if !strings.Contains(text, "s3:GetObject") || !strings.Contains(text, ".zip") {
				t.Fatal("build does not pin the one artifact object")
			}
		}
		if r["Type"] == "AWS::Lambda::MicrovmImage" {
			b, _ := json.Marshal(p)
			text := string(b)
			if strings.Contains(text, "ExecutionRole") || strings.Contains(text, "ALL\"") || strings.Contains(text, "customer") {
				t.Fatal("unsafe image authority or state")
			}
			if !strings.Contains(text, `"Ready":"ENABLED"`) || !strings.Contains(text, `"Validate":"ENABLED"`) {
				t.Fatal("missing lifecycle validation")
			}
			if p["Hooks"].(map[string]any)["MicrovmHooks"] != nil {
				t.Fatal("redundant per-request hook delays fresh VM admission")
			}
			if r["DependsOn"] == nil {
				t.Fatal("image build can race its artifact permissions")
			}
		}
	}
}

func TestMicroVMCreationUsesSupportedProjectScopedAuthorization(t *testing.T) {
	defer jsii.Close()
	stack := awscdk.NewStack(awscdk.NewApp(nil), jsii.String("PolicyTest"), nil)
	statements := htmlDeploymentStatements("111111111111", "us-east-2")
	awsiam.NewManagedPolicy(stack, jsii.String("HTMLPolicy"), &awsiam.ManagedPolicyProps{Statements: &statements})
	template := assertions.Template_FromStack(stack, nil)
	template.HasResourceProperties(jsii.String("AWS::IAM::ManagedPolicy"), map[string]any{
		"PolicyDocument": map[string]any{"Statement": assertions.Match_ArrayWith(&[]any{map[string]any{
			"Action": []any{"lambda:CreateMicrovmImage", "lambda:TagResource"}, "Resource": "*", "Effect": "Allow",
			"Condition": map[string]any{"StringEquals": map[string]any{"aws:RequestedRegion": "us-east-2", "aws:RequestTag/Project": "agent-pdf"}, "ForAllValues:StringEquals": map[string]any{"aws:TagKeys": []any{"Project"}}},
		}})},
	})
}

func TestHTMLMicroVMMemoryBounds(t *testing.T) {
	for input, want := range map[string]int{"": 512, "512": 512, "1024": 1024, "2048": 2048} {
		if got := htmlMicroVMMemory(input); got != want {
			t.Fatal(input, got)
		}
	}
	for _, input := range []string{"0", "256", "4096", "1024.0", "1024junk"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("unbounded memory accepted: %s", input)
				}
			}()
			htmlMicroVMMemory(input)
		}()
	}
}
