package main

import (
	"encoding/json"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
	"strings"
	"testing"
)

func TestCloudFrontAccessLogsMinimizeFieldsAndExpireWithinOneWeek(t *testing.T) {
	app := awscdk.NewApp(nil)
	stack := cloudFrontAccessLogsStack(app, "111111111111", "EAAAAAAAAAAAAA")
	template := assertions.Template_FromStack(stack, nil)
	template.HasResourceProperties(jsii.String("AWS::Logs::LogGroup"), map[string]any{"RetentionInDays": 7})
	resources := (*template.ToJSON())["Resources"].(map[string]any)
	found := false
	for _, raw := range resources {
		resource := raw.(map[string]any)
		p := resource["Properties"].(map[string]any)
		if resource["Type"] == "AWS::Logs::Delivery" {
			found = true
			tags, ok := p["Tags"].([]any)
			if !ok || len(tags) != 1 {
				t.Fatal("missing dedicated delivery ownership tag")
			}
			tag := tags[0].(map[string]any)
			if tag["Key"] != "Purpose" || tag["Value"] != "utils-bot-cloudfront-access" {
				t.Fatal("delivery ownership does not match IAM")
			}
			fields := p["RecordFields"].([]any)
			allowed := map[string]bool{"date": true, "time": true, "cs-method": true, "sc-status": true, "time-taken": true, "x-edge-result-type": true, "x-edge-response-result-type": true, "x-edge-detailed-result-type": true}
			if len(fields) != len(allowed) {
				t.Fatal("log field set changed")
			}
			for _, f := range fields {
				if !allowed[f.(string)] {
					t.Fatal("unapproved customer field recorded", f)
				}
			}
		}
		if resource["Type"] == "AWS::Logs::ResourcePolicy" {
			policy, _ := json.Marshal(p["PolicyDocument"])
			for _, required := range []string{"delivery.logs.amazonaws.com", "aws:SourceAccount", "aws:SourceArn", "ArnEquals", "agent-pdf-cloudfront-access-v2:log-stream:"} {
				if !strings.Contains(string(policy), required) {
					t.Fatal("delivery permissions lost scope", required)
				}
			}
		}
	}
	if !found {
		t.Fatal("missing log delivery")
	}
}

func TestCloudFrontAccessLogsAssemblyUsesCallerAndDedicatedExecutionRole(t *testing.T) {
	app := awscdk.NewApp(nil)
	stack := cloudFrontAccessLogsStack(app, "111111111111", "EAAAAAAAAAAAAA")
	artifact := app.Synth(nil).GetStackArtifact(stack.ArtifactId())
	role := artifact.CloudFormationExecutionRoleArn()
	if role == nil || *role != "arn:aws:iam::111111111111:role/utils-bot-cloudfront-logging-execution" {
		t.Fatal("logging assembly must select its dedicated execution role", role)
	}
	if role := artifact.AssumeRoleArn(); role != nil && *role != "" {
		t.Fatal("logging assembly must deploy using the current caller", *role)
	}
}
