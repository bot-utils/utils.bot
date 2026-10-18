package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudtrail"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	"github.com/aws/jsii-runtime-go"
)

const auditTrailName = "agent-pdf-management"

func auditTrailStack(app awscdk.App, account, region string, local bool) awscdk.Stack {
	stack := awscdk.NewStack(app, jsii.String("AgentPdfAudit"), &awscdk.StackProps{
		Env:                   &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)},
		Description:           jsii.String("Low-cost account-wide management-event audit trail"),
		TerminationProtection: stackTerminationProtection(local),
		// Audit deletion/update authority stays outside the ordinary application
		// deployment role so an app compromise cannot erase account evidence.
		Synthesizer: awscdk.NewCliCredentialsStackSynthesizer(nil),
	})
	awscdk.Tags_Of(stack).Add(jsii.String("Project"), jsii.String("agent-pdf"), nil)
	bucket := awss3.NewBucket(stack, jsii.String("TrailLogs"), &awss3.BucketProps{
		BucketName:        jsii.String("agent-pdf-cloudtrail-" + account + "-" + region),
		Encryption:        awss3.BucketEncryption_S3_MANAGED,
		BlockPublicAccess: awss3.BlockPublicAccess_BLOCK_ALL(),
		EnforceSSL:        jsii.Bool(true),
		MinimumTLSVersion: jsii.Number(1.2),
		ObjectOwnership:   awss3.ObjectOwnership_BUCKET_OWNER_ENFORCED,
		RemovalPolicy:     awscdk.RemovalPolicy_RETAIN,
		AutoDeleteObjects: jsii.Bool(false),
		LifecycleRules: &[]*awss3.LifecycleRule{{
			Id: jsii.String("ExpireAuditLogs"), Enabled: jsii.Bool(true),
			Expiration:                          awscdk.Duration_Days(jsii.Number(7)),
			AbortIncompleteMultipartUploadAfter: awscdk.Duration_Days(jsii.Number(1)),
		}},
	})
	awscloudtrail.NewTrail(stack, jsii.String("ManagementTrail"), &awscloudtrail.TrailProps{
		TrailName: jsii.String(auditTrailName), Bucket: bucket,
		ManagementEvents:   awscloudtrail.ReadWriteType_ALL,
		IsMultiRegionTrail: jsii.Bool(true), IncludeGlobalServiceEvents: jsii.Bool(true),
		EnableFileValidation: jsii.Bool(true), SendToCloudWatchLogs: jsii.Bool(false),
	})
	awscdk.NewCfnOutput(stack, jsii.String("AuditTrailName"), &awscdk.CfnOutputProps{Value: jsii.String(auditTrailName)})
	return stack
}
