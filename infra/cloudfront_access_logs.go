package main

import (
	"regexp"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/jsii-runtime-go"
)

// CloudFront standard logging v2 delivery is managed in us-east-1 and is
// separate from the distribution stack. The explicit distribution ID keeps
// the source ARN scoped to the one existing distribution.
func cloudFrontAccessLogsStack(app awscdk.App, account, distributionID string) awscdk.Stack {
	if !regexp.MustCompile(`^E[A-Z0-9]{10,}$`).MatchString(distributionID) {
		panic("PDF_CLOUDFRONT_DISTRIBUTION_ID must be the existing CloudFront distribution ID")
	}
	stack := awscdk.NewStack(app, jsii.String("AgentPdfCloudFrontAccessLogs"), &awscdk.StackProps{
		Env:         &awscdk.Environment{Account: jsii.String(account), Region: jsii.String("us-east-1")},
		Description: jsii.String("Privacy-minimized CloudFront standard logging v2 delivery"),
		// Deploy with the caller credentials and pass only the logging role.
		// This stack does not use the PDF/HTML deployment identity or boundary.
		Synthesizer: newCloudFrontLoggingSynthesizer(account),
	})
	awscdk.Tags_Of(stack).Add(jsii.String("Project"), jsii.String("agent-pdf"), nil)

	group := awslogs.NewLogGroup(stack, jsii.String("AccessLogs"), &awslogs.LogGroupProps{
		LogGroupName:  jsii.String("agent-pdf-cloudfront-access-v2"),
		Retention:     awslogs.RetentionDays_ONE_WEEK,
		RemovalPolicy: awscdk.RemovalPolicy_RETAIN,
	})
	resourceArn := "arn:aws:cloudfront::" + account + ":distribution/" + distributionID
	source := awscdk.NewCfnResource(stack, jsii.String("DeliverySource"), &awscdk.CfnResourceProps{
		Type: jsii.String("AWS::Logs::DeliverySource"),
		Properties: &map[string]interface{}{
			"Name":        "agent-pdf-cloudfront-access-v2",
			"ResourceArn": resourceArn,
			"LogType":     "ACCESS_LOGS",
		},
	})
	destination := awscdk.NewCfnResource(stack, jsii.String("DeliveryDestination"), &awscdk.CfnResourceProps{
		Type: jsii.String("AWS::Logs::DeliveryDestination"),
		Properties: &map[string]interface{}{
			"Name":                    "agent-pdf-cloudfront-access-v2",
			"DeliveryDestinationType": "CWL",
			"DestinationResourceArn":  group.LogGroupArn(),
			"OutputFormat":            "json",
		},
	})
	resourcePolicy := awscdk.NewCfnResource(stack, jsii.String("DeliveryWritePolicy"), &awscdk.CfnResourceProps{
		Type: jsii.String("AWS::Logs::ResourcePolicy"),
		Properties: &map[string]interface{}{
			"PolicyName": "agent-pdf-cloudfront-access-v2",
			"PolicyDocument": map[string]interface{}{
				"Version": "2012-10-17",
				"Statement": []interface{}{map[string]interface{}{
					"Effect":    "Allow",
					"Principal": map[string]interface{}{"Service": "delivery.logs.amazonaws.com"},
					"Action":    []string{"logs:CreateLogStream", "logs:PutLogEvents"},
					"Resource":  "arn:aws:logs:us-east-1:" + account + ":log-group:agent-pdf-cloudfront-access-v2:log-stream:*",
					"Condition": map[string]interface{}{
						"StringEquals": map[string]interface{}{"aws:SourceAccount": account},
						"ArnEquals":    map[string]interface{}{"aws:SourceArn": source.GetAtt(jsii.String("Arn"), awscdk.ResolutionTypeHint_STRING).ToString()},
					},
				}},
			},
		},
	})
	delivery := awscdk.NewCfnResource(stack, jsii.String("Delivery"), &awscdk.CfnResourceProps{
		Type: jsii.String("AWS::Logs::Delivery"),
		Properties: &map[string]interface{}{
			"DeliverySourceName":     "agent-pdf-cloudfront-access-v2",
			"DeliveryDestinationArn": destination.GetAtt(jsii.String("Arn"), awscdk.ResolutionTypeHint_STRING).ToString(),
			"Tags":                   []map[string]string{{"Key": "Purpose", "Value": "utils-bot-cloudfront-access"}},
			// Keep the field list private by default: no IP address, host,
			// URI, query, cookie, referrer, user agent, or request ID.
			"RecordFields": []string{
				"date", "time", "cs-method", "sc-status", "time-taken",
				"x-edge-result-type", "x-edge-response-result-type", "x-edge-detailed-result-type",
			},
		},
	})
	delivery.AddDependency(source)
	delivery.AddDependency(destination)
	delivery.AddDependency(resourcePolicy)
	awscdk.NewCfnOutput(stack, jsii.String("CloudFrontAccessLogGroup"), &awscdk.CfnOutputProps{Value: group.LogGroupName()})
	return stack
}

// This stack has no assets and deploys with the caller credentials. CDK's
// BootstraplessSynthesizer still defaults to a bootstrap deploy role when its
// DeployRoleArn is omitted, so emit only the dedicated execution role here.
type assetFreeSynthesizer struct {
	awscdk.StackSynthesizer
	executionRole *string
}

func newCloudFrontLoggingSynthesizer(account string) awscdk.IStackSynthesizer {
	return newAssetFreeSynthesizer(namedRoleArn(account, "utils-bot-cloudfront-logging-execution"))
}

func newAssetFreeSynthesizer(role string) awscdk.IStackSynthesizer {
	s := &assetFreeSynthesizer{executionRole: jsii.String(role)}
	awscdk.NewStackSynthesizer_Override(s)
	return s
}

func (s *assetFreeSynthesizer) CloudFormationExecutionRole() *string {
	return s.executionRole
}

func (s *assetFreeSynthesizer) Synthesize(session awscdk.ISynthesisSession) {
	s.SynthesizeStackTemplate(s.BoundStack(), session)
	s.EmitArtifact(session, &awscdk.SynthesizeStackArtifactOptions{CloudFormationExecutionRoleArn: s.executionRole})
}

func (s *assetFreeSynthesizer) AddFileAsset(_ *awscdk.FileAssetSource) *awscdk.FileAssetLocation {
	panic("asset-free stack does not support file assets")
}

func (s *assetFreeSynthesizer) AddDockerImageAsset(_ *awscdk.DockerImageAssetSource) *awscdk.DockerImageAssetLocation {
	panic("asset-free stack does not support image assets")
}
