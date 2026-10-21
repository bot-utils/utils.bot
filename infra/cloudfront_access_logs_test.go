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
