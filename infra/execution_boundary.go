package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

func allow(actions, resources *[]*string, conditions ...*map[string]interface{}) awsiam.PolicyStatement {
	props := &awsiam.PolicyStatementProps{Actions: actions, Resources: resources}
	if len(conditions) == 1 {
		props.Conditions = conditions[0]
	}
	return awsiam.NewPolicyStatement(props)
}

func regionalCondition(region string) *map[string]interface{} {
	return &map[string]interface{}{"StringEquals": map[string]any{"aws:RequestedRegion": region}}
}

func networkDeploymentStatements(account, region string) []awsiam.PolicyStatement {
	vpcs := jsii.Strings("arn:aws:ec2:" + region + ":" + account + ":vpc/*")
	rootResources := jsii.Strings(
		"arn:aws:ec2:"+region+":"+account+":vpc/*",
		"arn:aws:ec2:"+region+":"+account+":internet-gateway/*",
	)
	childResources := jsii.Strings(
		"arn:aws:ec2:"+region+":"+account+":subnet/*",
		"arn:aws:ec2:"+region+":"+account+":route-table/*",
		"arn:aws:ec2:"+region+":"+account+":security-group/*",
	)
	resources := append([]*string{}, (*rootResources)...)
	resources = append(resources, (*childResources)...)
	allResources := &resources
	newResourceTag := &map[string]interface{}{"StringEquals": map[string]any{"aws:RequestTag/Project": "agent-pdf"}}
	ownedResource := &map[string]interface{}{"StringEquals": map[string]any{"aws:ResourceTag/Project": "agent-pdf"}}
	return []awsiam.PolicyStatement{
		allow(jsii.Strings("ec2:DescribeAccountAttributes", "ec2:DescribeAvailabilityZones", "ec2:DescribeInternetGateways", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets", "ec2:DescribeTags", "ec2:DescribeVpcs"), jsii.Strings("*"), regionalCondition(region)),
		allow(jsii.Strings("ec2:CreateInternetGateway", "ec2:CreateVpc"), rootResources, newResourceTag),
		// Child creation is authorized twice by EC2: once for the new child,
		// which must carry the Project tag, and once for its parent VPC, which
		// must already be owned. This prevents creating PDF resources inside an
		// unrelated VPC.
		allow(jsii.Strings("ec2:CreateRouteTable", "ec2:CreateSecurityGroup", "ec2:CreateSubnet"), childResources, newResourceTag),
		allow(jsii.Strings("ec2:CreateRouteTable", "ec2:CreateSecurityGroup", "ec2:CreateSubnet"), vpcs, ownedResource),
		// EC2 performs a separate CreateTags authorization for tags supplied to
		// a create API. ec2:CreateAction confines this permission to that atomic
		// operation, so it cannot be used to adopt an unrelated live resource.
		allow(jsii.Strings("ec2:CreateTags"), allResources, &map[string]interface{}{"StringEquals": map[string]any{
			"aws:RequestTag/Project": "agent-pdf",
			"ec2:CreateAction":       []string{"CreateInternetGateway", "CreateRouteTable", "CreateSecurityGroup", "CreateSubnet", "CreateVpc"},
		}}),
		allow(jsii.Strings("ec2:CreateTags", "ec2:DeleteTags"), allResources, ownedResource),
		allow(jsii.Strings("ec2:AssociateRouteTable", "ec2:AttachInternetGateway", "ec2:AuthorizeSecurityGroupEgress", "ec2:AuthorizeSecurityGroupIngress", "ec2:CreateRoute", "ec2:DeleteInternetGateway", "ec2:DeleteRoute", "ec2:DeleteRouteTable", "ec2:DeleteSecurityGroup", "ec2:DeleteSubnet", "ec2:DeleteVpc", "ec2:DetachInternetGateway", "ec2:DisassociateRouteTable", "ec2:ModifySecurityGroupRules", "ec2:ModifySubnetAttribute", "ec2:ModifyVpcAttribute", "ec2:RevokeSecurityGroupEgress", "ec2:RevokeSecurityGroupIngress", "ec2:UpdateSecurityGroupRuleDescriptionsEgress", "ec2:UpdateSecurityGroupRuleDescriptionsIngress"), allResources, ownedResource),
	}
}

func networkBoundaryStatements(account, region string) []awsiam.PolicyStatement {
	vpcs := jsii.Strings("arn:aws:ec2:" + region + ":" + account + ":vpc/*")
	rootResources := jsii.Strings(
		"arn:aws:ec2:"+region+":"+account+":vpc/*",
		"arn:aws:ec2:"+region+":"+account+":internet-gateway/*",
	)
	childResources := jsii.Strings(
		"arn:aws:ec2:"+region+":"+account+":subnet/*",
		"arn:aws:ec2:"+region+":"+account+":route-table/*",
		"arn:aws:ec2:"+region+":"+account+":security-group/*",
	)
	resources := append([]*string{}, (*rootResources)...)
	resources = append(resources, (*childResources)...)
	allResources := &resources
	requestTag := &map[string]interface{}{"StringEquals": map[string]any{"aws:RequestTag/Project": "agent-pdf"}}
	owned := &map[string]interface{}{"StringEquals": map[string]any{"aws:ResourceTag/Project": "agent-pdf"}}
	return []awsiam.PolicyStatement{
		allow(jsii.Strings("ec2:Describe*"), jsii.Strings("*"), regionalCondition(region)),
		allow(jsii.Strings("ec2:CreateInternetGateway", "ec2:CreateVpc"), rootResources, requestTag),
		allow(jsii.Strings("ec2:CreateRouteTable", "ec2:CreateSecurityGroup", "ec2:CreateSubnet"), childResources, requestTag),
		allow(jsii.Strings("ec2:CreateRouteTable", "ec2:CreateSecurityGroup", "ec2:CreateSubnet"), vpcs, owned),
		allow(jsii.Strings("ec2:CreateTags"), allResources, &map[string]interface{}{"StringEquals": map[string]any{
			"aws:RequestTag/Project": "agent-pdf",
			"ec2:CreateAction":       []string{"CreateInternetGateway", "CreateRouteTable", "CreateSecurityGroup", "CreateSubnet", "CreateVpc"},
		}}),
		// The attached identity policy retains the exact action list. These
		// boundary action families are limited to resources already carrying the
		// PDF ownership tag and therefore cannot affect unrelated infrastructure.
		allow(jsii.Strings("ec2:Associate*", "ec2:AttachInternetGateway", "ec2:AuthorizeSecurityGroup*", "ec2:CreateRoute", "ec2:CreateTags", "ec2:Delete*", "ec2:DetachInternetGateway", "ec2:Disassociate*", "ec2:Modify*", "ec2:RevokeSecurityGroup*", "ec2:UpdateSecurityGroup*"), allResources, owned),
	}
}

func executionServiceBoundaryStatements(account, region, zone, distributionID, originPolicyID, viewerCertificateARN, originCertificateARN string, additionalOwnedARNs ...string) []awsiam.PolicyStatement {
	owned := jsii.Strings(
		"arn:aws:ecs:"+region+":"+account+":*/*agent-pdf-mock*",
		"arn:aws:ecs:"+region+":"+account+":*/*AgentPdfMock-*",
		"arn:aws:elasticloadbalancing:"+region+":"+account+":*/*agent-pdf-mock*",
		"arn:aws:dynamodb:"+region+":"+account+":table/agent-pdf-*-payments",
		"arn:aws:lambda:"+region+":"+account+":*:agent-pdf-*",
		"arn:aws:events:"+region+":"+account+":rule/agent-pdf-html-threat-refresh",
		"arn:aws:logs:"+region+":"+account+":log-group:/agent-pdf/mock/*",
		"arn:aws:sns:"+region+":"+account+":agent-pdf-alerts",
		"arn:aws:wafv2:us-east-1:"+account+":global/ipset/agent-pdf-owner/*",
		"arn:aws:wafv2:us-east-1:"+account+":global/webacl/agent-pdf-edge/*",
		"arn:aws:wafv2:"+region+":"+account+":regional/webacl/agent-pdf-mock/*",
		"arn:aws:cloudwatch:"+region+":"+account+":alarm:agent-pdf-*",
		"arn:aws:cloudwatch::"+account+":dashboard/agent-pdf",
		"arn:aws:budgets::"+account+":budget/agent-pdf-fargate-monthly",
		"arn:aws:cloudfront::"+account+":distribution/"+distributionID,
		"arn:aws:cloudfront::"+account+":function/agent-pdf-*",
		"arn:aws:cloudfront::"+account+":origin-request-policy/"+originPolicyID,
		viewerCertificateARN,
		originCertificateARN,
		"arn:aws:route53:::hostedzone/"+zone,
		"arn:aws:route53:::change/*",
		"arn:aws:s3:::cdk-hnb659fds-assets-"+account+"-"+region+"/*",
		"arn:aws:ssm:"+region+":"+account+":parameter/cdk-bootstrap/hnb659fds/version",
	)
	for _, arn := range additionalOwnedARNs {
		if arn != "" {
			*owned = append(*owned, jsii.String(arn))
		}
	}
	statements := []awsiam.PolicyStatement{
		// Identity policies still enumerate asset reads. Compact the read-only
		// boundary family to stay within IAM's 6,144-character document limit.
		allow(jsii.Strings("events:*", "ecs:*", "elasticloadbalancing:*", "dynamodb:*", "lambda:*", "logs:*", "sns:*", "wafv2:*", "cloudwatch:*", "budgets:*", "cloudfront:*", "acm:*", "route53:*", "s3:GetObject*", "ssm:GetParameters"), owned),
		// Compact this ceiling for APIs needing wildcard scope and managed network
		// connector passes. Identity policies pin connector ARNs and retain the
		// exact action, region, domain and tag limits.
		allow(jsii.Strings("lambda:CreateMicrovmImage", "lambda:TagResource", "lambda:PassNetworkConnector", "acm:RequestCertificate", "cloudfront:CreateOriginAccessControl", "application-autoscaling:*ScalableTarget", "application-autoscaling:*ScalingPolicy", "application-autoscaling:*Tag*", "application-autoscaling:Describe*", "cloudwatch:Describe*", "ecs:Describe*", "elasticloadbalancing:Describe*", "logs:Describe*"), jsii.Strings("*")),
	}
	// The attached identity policy enumerates exact bucket-management actions.
	// This covers website/public-threat bucket metadata, excluding objects,
	// bootstrap state and unrelated buckets.
	statements = append(statements, staticSiteBoundaryStatement(account, region))

	return append(statements, networkBoundaryStatements(account, region)...)
}
