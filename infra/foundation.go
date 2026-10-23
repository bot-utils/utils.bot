package main

import (
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

const (
	executionRoleName     = "agent-pdf-cloudformation-execution"
	executionBoundaryName = "agent-pdf-execution-boundary"
	runtimeBoundaryName   = "agent-pdf-runtime-boundary"
)

func namedRoleArn(account, name string) string {
	return "arn:aws:iam::" + account + ":role/" + name
}

func namedPolicyArn(account, name string) string {
	return "arn:aws:iam::" + account + ":policy/" + name
}

func requiredFoundationResourceID(name string) string {
	value := os.Getenv(name)
	if !regexp.MustCompile(`^[A-Za-z0-9-]{8,128}$`).MatchString(value) {
		panic("missing or invalid " + name)
	}
	return value
}

func requiredFoundationARN(name, prefix string) string {
	value := os.Getenv(name)
	if !strings.HasPrefix(value, prefix) || !regexp.MustCompile(`^arn:aws:acm:[a-z0-9-]+:[0-9]{12}:certificate/[A-Za-z0-9-]+$`).MatchString(value) {
		panic("missing or invalid " + name)
	}
	return value
}

func pdfStackSynthesizer(account string) awscdk.IStackSynthesizer {
	if !dedicatedExecutionSetting(os.Getenv("PDF_USE_DEDICATED_EXECUTION_ROLE")) {
		return nil
	}
	return awscdk.NewDefaultStackSynthesizer(&awscdk.DefaultStackSynthesizerProps{
		CloudFormationExecutionRole: jsii.String(namedRoleArn(account, executionRoleName)),
	})
}

func pdfEdgeSynthesizer(account string) awscdk.IStackSynthesizer {
	execution := "arn:aws:iam::" + account + ":role/cdk-hnb659fds-cfn-exec-role-" + account + "-us-east-2"
	if dedicatedExecutionSetting(os.Getenv("PDF_USE_DEDICATED_EXECUTION_ROLE")) {
		execution = namedRoleArn(account, executionRoleName)
	}
	return awscdk.NewBootstraplessSynthesizer(&awscdk.BootstraplessSynthesizerProps{
		DeployRoleArn:                  jsii.String("arn:aws:iam::" + account + ":role/cdk-hnb659fds-deploy-role-" + account + "-us-east-2"),
		CloudFormationExecutionRoleArn: jsii.String(execution),
	})
}

func dedicatedExecutionSetting(value string) bool {
	switch value {
	case "", "0":
		return false
	case "1":
		return true
	default:
		panic("PDF_USE_DEDICATED_EXECUTION_ROLE must be 0 or 1")
	}
}

func applyRuntimeBoundary(stack awscdk.Stack, account string, local bool) {
	if local || !dedicatedExecutionSetting(os.Getenv("PDF_USE_DEDICATED_EXECUTION_ROLE")) {
		return
	}
	boundary := awsiam.ManagedPolicy_FromManagedPolicyArn(stack, jsii.String("RuntimeBoundary"), jsii.String(namedPolicyArn(account, runtimeBoundaryName)))
	awsiam.PermissionsBoundary_Of(stack).Apply(boundary)
}

func foundationStack(app awscdk.App, account, region string) awscdk.Stack {
	stack := awscdk.NewStack(app, jsii.String("AgentPdfFoundation"), &awscdk.StackProps{
		Env:                   &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)},
		Description:           jsii.String("Dedicated bounded CloudFormation execution identity for agent-pdf"),
		TerminationProtection: jsii.Bool(true),
		// The ordinary bootstrap execution role must never receive permissions
		// to edit this role or its boundaries. Foundation creation and later
		// maintenance intentionally require an owner/admin credential session.
		Synthesizer: awscdk.NewCliCredentialsStackSynthesizer(nil),
	})
	awscdk.Tags_Of(stack).Add(jsii.String("Project"), jsii.String("agent-pdf"), nil)

	runtimeBoundary := awsiam.NewManagedPolicy(stack, jsii.String("RuntimePermissionsBoundary"), &awsiam.ManagedPolicyProps{
		ManagedPolicyName: jsii.String(runtimeBoundaryName),
		Description:       jsii.String("Maximum permissions for PDF Lambda and ECS runtime roles"),
		Statements: &[]awsiam.PolicyStatement{
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"), Resources: jsii.Strings("arn:aws:dynamodb:"+region+":"+account+":table/agent-pdf-mock-payments", "arn:aws:dynamodb:"+region+":"+account+":table/agent-pdf-html-test-payments")}),
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("ssm:GetParameters"), Resources: jsii.Strings("arn:aws:ssm:us-east-1:"+account+":parameter/pdf/coinbaseAPIKey", "arn:aws:ssm:us-east-1:"+account+":parameter/pdf/coinbaseAPISecret", "arn:aws:ssm:us-east-1:"+account+":parameter/pdf/receiveAddress")}),
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("lambda:InvokeFunction"), Resources: jsii.Strings("arn:aws:lambda:"+region+":"+account+":function:agent-pdf-mock-payment:live", "arn:aws:lambda:"+region+":"+account+":function:agent-pdf-html-worker:live", "arn:aws:lambda:"+region+":"+account+":function:agent-pdf-html-test-payment:live")}),
			allow(jsii.Strings("lambda:PassNetworkConnector"), jsii.Strings("arn:aws:lambda:"+region+":aws:network-connector:aws-network-connector:INTERNET_EGRESS", "arn:aws:lambda:"+region+":aws:network-connector:aws-network-connector:ALL_INGRESS")),
			allow(jsii.Strings("lambda:RunMicrovm", "lambda:GetMicrovm", "lambda:TerminateMicrovm", "lambda:CreateMicrovmAuthToken"), jsii.Strings("arn:aws:lambda:"+region+":"+account+":microvm-image:agent-pdf-html*")),
			allow(jsii.Strings("s3:GetObject"), jsii.Strings("arn:aws:s3:::cdk-hnb659fds-assets-"+account+"-"+region+"/*")),
			allow(jsii.Strings("s3:GetObject", "s3:PutObject"), jsii.Strings("arn:aws:s3:::"+threatBucketName(account)+"/threats/v2/*")),
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"), Resources: jsii.Strings("arn:aws:ecr:" + region + ":" + account + ":repository/cdk-hnb659fds-container-assets-" + account + "-" + region)}),
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("ecr:GetAuthorizationToken"), Resources: jsii.Strings("*")}),
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"), Resources: jsii.Strings("arn:aws:logs:"+region+":"+account+":log-group:/agent-pdf/mock/*", "arn:aws:logs:"+region+":"+account+":log-group:/aws/lambda/agent-pdf-mock-payment*")}),
		},
	})

	// Explicit expiring validation ceiling, absent on ordinary builds. Boundary
	// maintenance uses the existing owner path, never the application deployer.
	if csv, _ := csvPrivateSettings(); csv != nil {
		if csv.Account != account {
			panic("private CSV boundary account differs")
		}
		for _, statement := range csvBoundaryStatements(account, *csv) {
			runtimeBoundary.AddStatements(statement)
		}
	}

	if os.Getenv("PDF_BOUNDARY_API_CERTIFICATE_ARN") != "" {
		requiredFoundationARN("PDF_BOUNDARY_API_CERTIFICATE_ARN", "arn:aws:acm:"+region+":"+account+":certificate/")
	}
	// The first private static deployment creates the OAC before its ID is
	// knowable. Refresh the protected foundation immediately afterward to pin
	// the exact ID; application deployments cannot edit this ceiling.
	staticOACARN := "arn:aws:cloudfront::" + account + ":origin-access-control/*"
	if os.Getenv("PDF_BOUNDARY_STATIC_OAC_ID") != "" {
		staticOACARN = "arn:aws:cloudfront::" + account + ":origin-access-control/" + requiredFoundationResourceID("PDF_BOUNDARY_STATIC_OAC_ID")
	}
	executionStatements := executionServiceBoundaryStatements(account, region, hostedZoneID(), requiredFoundationResourceID("PDF_BOUNDARY_CLOUDFRONT_DISTRIBUTION_ID"), requiredFoundationResourceID("PDF_BOUNDARY_ORIGIN_REQUEST_POLICY_ID"), requiredFoundationARN("PDF_BOUNDARY_VIEWER_CERTIFICATE_ARN", "arn:aws:acm:us-east-1:"+account+":certificate/"), requiredFoundationARN("PDF_BOUNDARY_ORIGIN_CERTIFICATE_ARN", "arn:aws:acm:"+region+":"+account+":certificate/"), os.Getenv("PDF_BOUNDARY_API_CERTIFICATE_ARN"), staticOACARN)
	executionStatements = append(executionStatements,
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("iam:GetRole*", "iam:List*RolePolic*", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:DeleteRole"), Resources: jsii.Strings("arn:aws:iam::" + account + ":role/AgentPdfMock-*")}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("iam:CreateRole", "iam:PutRolePermissionsBoundary"), Resources: jsii.Strings("arn:aws:iam::" + account + ":role/AgentPdfMock-*"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"iam:PermissionsBoundary": namedPolicyArn(account, runtimeBoundaryName)}}}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("iam:AttachRolePolicy", "iam:DetachRolePolicy"), Resources: jsii.Strings("arn:aws:iam::" + account + ":role/AgentPdfMock-*"), Conditions: &map[string]interface{}{"ArnEquals": map[string]any{"iam:PolicyARN": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"}}}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("iam:PassRole"), Resources: jsii.Strings("arn:aws:iam::" + account + ":role/AgentPdfMock-*"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"iam:PassedToService": []string{"ecs-tasks.amazonaws.com", "lambda.amazonaws.com"}}}}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("iam:CreateServiceLinkedRole"), Resources: jsii.Strings("arn:aws:iam::" + account + ":role/aws-service-role/ecs.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_ECSService"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"iam:AWSServiceName": "ecs.application-autoscaling.amazonaws.com"}}}),
	)
	executionBoundary := awsiam.NewManagedPolicy(stack, jsii.String("ExecutionPermissionsBoundary"), &awsiam.ManagedPolicyProps{
		ManagedPolicyName: jsii.String(executionBoundaryName),
		Description:       jsii.String("Service and IAM ceiling for the dedicated PDF CloudFormation role"),
		Statements:        &executionStatements,
	})

	scalingPolicy := awsiam.NewManagedPolicy(stack, jsii.String("AutoscalingDeploymentPolicy"), &awsiam.ManagedPolicyProps{ManagedPolicyName: jsii.String("PDF_AUTOSCALING_DEPLOY"), Statements: &[]awsiam.PolicyStatement{
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("iam:CreateServiceLinkedRole"), Resources: jsii.Strings("arn:aws:iam::" + account + ":role/aws-service-role/ecs.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_ECSService"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"iam:AWSServiceName": "ecs.application-autoscaling.amazonaws.com"}}}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("application-autoscaling:RegisterScalableTarget", "application-autoscaling:DeregisterScalableTarget", "application-autoscaling:PutScalingPolicy", "application-autoscaling:DeleteScalingPolicy", "application-autoscaling:DescribeScalableTargets", "application-autoscaling:DescribeScalingPolicies", "application-autoscaling:DescribeScalingActivities"), Resources: jsii.Strings("*"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"aws:RequestedRegion": region}}}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("application-autoscaling:TagResource"), Resources: jsii.Strings("arn:aws:application-autoscaling:" + region + ":" + account + ":scalable-target/*"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"aws:RequestTag/Project": "agent-pdf"}}}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("application-autoscaling:UntagResource"), Resources: jsii.Strings("arn:aws:application-autoscaling:" + region + ":" + account + ":scalable-target/*"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"aws:ResourceTag/Project": "agent-pdf"}}}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("application-autoscaling:ListTagsForResource"), Resources: jsii.Strings("arn:aws:application-autoscaling:" + region + ":" + account + ":scalable-target/*")}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:DescribeAlarms"), Resources: jsii.Strings("*"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"aws:RequestedRegion": region}}}),
	}})
	boundaryAttachmentPolicy := awsiam.NewManagedPolicy(stack, jsii.String("BoundaryAttachmentPolicy"), &awsiam.ManagedPolicyProps{ManagedPolicyName: jsii.String("PDF_RUNTIME_BOUNDARY_DEPLOY"), Statements: &[]awsiam.PolicyStatement{
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("iam:PutRolePermissionsBoundary"), Resources: jsii.Strings("arn:aws:iam::" + account + ":role/AgentPdfMock-*"), Conditions: &map[string]interface{}{"StringEquals": map[string]any{"iam:PermissionsBoundary": runtimeBoundary.ManagedPolicyArn()}}}),
	}})
	networkStatements := networkDeploymentStatements(account, region)
	networkPolicy := awsiam.NewManagedPolicy(stack, jsii.String("NetworkDeploymentPolicy"), &awsiam.ManagedPolicyProps{ManagedPolicyName: jsii.String("PDF_NETWORK_DEPLOY"), Statements: &networkStatements})
	htmlStatements := htmlDeploymentStatements(account, region)
	htmlPolicy := awsiam.NewManagedPolicy(stack, jsii.String("HtmlDeploymentPolicy"), &awsiam.ManagedPolicyProps{ManagedPolicyName: jsii.String("PDF_HTML_DEPLOY"), Statements: &htmlStatements})
	managed := []awsiam.IManagedPolicy{scalingPolicy, boundaryAttachmentPolicy, networkPolicy, htmlPolicy}
	for index, name := range []string{"PDF_CDK_DEPLOY", "PDF_CDK_DEPLOY_2", "PDF_EDGE_DEPLOY"} {
		managed = append(managed, awsiam.ManagedPolicy_FromManagedPolicyArn(stack, jsii.String("ExistingPolicy"+string(rune('A'+index))), jsii.String(namedPolicyArn(account, name))))
	}
	role := awsiam.NewRole(stack, jsii.String("CloudFormationExecutionRole"), &awsiam.RoleProps{
		RoleName:        jsii.String(executionRoleName),
		Description:     jsii.String("Dedicated bounded execution role for agent-pdf CloudFormation stacks"),
		AssumedBy:       awsiam.NewServicePrincipal(jsii.String("cloudformation.amazonaws.com"), nil),
		ManagedPolicies: &managed, PermissionsBoundary: executionBoundary,
	})
	role.AddToPolicy(staticSiteManagementStatement(account, region))
	role.AddToPolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("ssm:GetParameters"), Resources: jsii.Strings("arn:aws:ssm:" + region + ":" + account + ":parameter/cdk-bootstrap/hnb659fds/version")}))
	awsiam.NewCfnPolicy(stack, jsii.String("BootstrapPassDedicatedExecutionRole"), &awsiam.CfnPolicyProps{
		PolicyName: jsii.String("agent-pdf-pass-dedicated-execution"),
		Roles:      jsii.Strings("cdk-hnb659fds-deploy-role-" + account + "-" + region),
		PolicyDocument: map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
			"Effect": "Allow", "Action": "iam:PassRole", "Resource": role.RoleArn(),
			"Condition": map[string]any{"StringEquals": map[string]any{"iam:PassedToService": "cloudformation.amazonaws.com"}},
		}}},
	})
	awscdk.NewCfnOutput(stack, jsii.String("DedicatedExecutionRoleArn"), &awscdk.CfnOutputProps{Value: role.RoleArn()})
	awscdk.NewCfnOutput(stack, jsii.String("RuntimeBoundaryArn"), &awscdk.CfnOutputProps{Value: runtimeBoundary.ManagedPolicyArn()})
	return stack
}
