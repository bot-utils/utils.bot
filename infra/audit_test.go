package main

import (
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
)

func TestAuditTrailIsSingleLowCostManagementCopyWithShortPrivateRetention(t *testing.T) {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := auditTrailStack(app, "111111111111", "us-east-2", false)
	template := assertions.Template_FromStack(stack, nil)
	template.HasResourceProperties(jsii.String("AWS::CloudTrail::Trail"), map[string]any{
		"TrailName":                  auditTrailName,
		"IsLogging":                  true,
		"IsMultiRegionTrail":         true,
		"IncludeGlobalServiceEvents": true,
		"EnableLogFileValidation":    true,
		"EventSelectors": []any{map[string]any{
			"IncludeManagementEvents": true,
			"ReadWriteType":           "All",
		}},
	})
	template.ResourceCountIs(jsii.String("AWS::Logs::LogGroup"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::KMS::Key"), jsii.Number(0))
	template.HasResourceProperties(jsii.String("AWS::S3::Bucket"), map[string]any{
		"BucketEncryption": map[string]any{"ServerSideEncryptionConfiguration": []any{map[string]any{"ServerSideEncryptionByDefault": map[string]any{"SSEAlgorithm": "AES256"}}}},
		"PublicAccessBlockConfiguration": map[string]any{
			"BlockPublicAcls": true, "BlockPublicPolicy": true,
			"IgnorePublicAcls": true, "RestrictPublicBuckets": true,
		},
		"LifecycleConfiguration": map[string]any{"Rules": []any{map[string]any{
			"Id": "ExpireAuditLogs", "Status": "Enabled", "ExpirationInDays": 7,
			"AbortIncompleteMultipartUpload": map[string]any{"DaysAfterInitiation": 1},
		}}},
	})
	resources := (*template.ToJSON())["Resources"].(map[string]interface{})
	for _, raw := range resources {
		resource := raw.(map[string]interface{})
		if resource["Type"] == "AWS::S3::Bucket" {
			if resource["DeletionPolicy"] != "Retain" || resource["UpdateReplacePolicy"] != "Retain" {
				t.Fatal("audit evidence bucket must survive stack replacement or deletion")
			}
		}
	}
	if stack.TerminationProtection() == nil || !*stack.TerminationProtection() {
		t.Fatal("audit stack lacks termination protection")
	}
}
