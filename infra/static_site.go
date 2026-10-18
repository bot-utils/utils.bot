package main

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscertificatemanager"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudfront"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudfrontorigins"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsroute53"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	"github.com/aws/jsii-runtime-go"
	"os"
)

func staticSiteEnabled() bool {
	switch os.Getenv("PDF_STATIC_SITE") {
	case "", "0":
		return false
	case "1":
		if !directAPIEnabled() {
			panic("static site requires the regional API")
		}
		return true
	default:
		panic("PDF_STATIC_SITE must be 0 or 1")
	}
}

// Pure static objects use one cache behavior; /health alone checks the receiver.
// No custom cache/header/origin-request policy or deployment Lambda is added.
// This prepares a small configuration for Free-plan review, not proof of eligibility.
func staticSiteDistribution(stack awscdk.Stack, healthOrigin awscloudfront.IOrigin, viewerCert, webACL *string) awscloudfront.Distribution {
	bucket := awss3.NewBucket(stack, jsii.String("WebsiteAssets"), &awss3.BucketProps{BucketName: jsii.String(staticSiteBucketName(*stack.Account(), *stack.Region())), BlockPublicAccess: awss3.BlockPublicAccess_BLOCK_ALL(), ObjectOwnership: awss3.ObjectOwnership_BUCKET_OWNER_ENFORCED, Encryption: awss3.BucketEncryption_S3_MANAGED, EnforceSSL: jsii.Bool(true), Versioned: jsii.Bool(false), RemovalPolicy: awscdk.RemovalPolicy_RETAIN})
	// Even a mistakenly uploaded non-public object cannot be retrieved through OAC.
	bucket.AddToResourcePolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Effect: awsiam.Effect_DENY, Principals: &[]awsiam.IPrincipal{awsiam.NewAnyPrincipal()}, Actions: jsii.Strings("s3:GetObject"), NotResources: jsii.Strings(*bucket.BucketArn() + "/public/*")}))
	functions := []awscloudfront.Function{}
	for _, name := range []string{"REQUEST", "RESPONSE"} {
		code, err := os.ReadFile(os.Getenv("PDF_SITE_" + name + "_CODE_FILE"))
		if err != nil {
			panic(err)
		}
		if len(code) > 10<<10 {
			panic("static function exceeds CloudFront code limit")
		}
		functions = append(functions, awscloudfront.NewFunction(stack, jsii.String("Website"+name), &awscloudfront.FunctionProps{FunctionName: jsii.String("agent-pdf-site-" + name), Runtime: awscloudfront.FunctionRuntime_JS_2_0(), Code: awscloudfront.FunctionCode_FromInline(jsii.String(string(code))), AutoPublish: jsii.Bool(true)}))
	}
	associations := &[]*awscloudfront.FunctionAssociation{{Function: functions[0], EventType: awscloudfront.FunctionEventType_VIEWER_REQUEST}, {Function: functions[1], EventType: awscloudfront.FunctionEventType_VIEWER_RESPONSE}}
	behavior := func(origin awscloudfront.IOrigin, cache awscloudfront.ICachePolicy) *awscloudfront.BehaviorOptions {
		return &awscloudfront.BehaviorOptions{Origin: origin, CachePolicy: cache, AllowedMethods: awscloudfront.AllowedMethods_ALLOW_ALL(), ViewerProtocolPolicy: awscloudfront.ViewerProtocolPolicy_HTTPS_ONLY, FunctionAssociations: associations}
	}
	// POST is allowed at CloudFront only so its viewer function can return the
	// canonical API redirect; the function never forwards it to S3 or /health.
	distribution := awscloudfront.NewDistribution(stack, jsii.String("Frontend"), &awscloudfront.DistributionProps{PriceClass: awscloudfront.PriceClass_PRICE_CLASS_100, DefaultBehavior: behavior(awscloudfrontorigins.S3BucketOrigin_WithOriginAccessControl(bucket, nil), awscloudfront.CachePolicy_CACHING_OPTIMIZED()), AdditionalBehaviors: &map[string]*awscloudfront.BehaviorOptions{"/health": behavior(healthOrigin, awscloudfront.CachePolicy_CACHING_DISABLED())}, DomainNames: jsii.Strings(domain), Certificate: awscertificatemanager.Certificate_FromCertificateArn(stack, jsii.String("ViewerCertificate"), viewerCert), WebAclId: webACL, MinimumProtocolVersion: awscloudfront.SecurityPolicyProtocol_TLS_V1_2_2021, EnableIpv6: jsii.Bool(false), EnableLogging: jsii.Bool(false), GeoRestriction: awscloudfront.GeoRestriction_Denylist((*jsii.Strings(cloudFrontBlockedCountries()...))...), ErrorResponses: &[]*awscloudfront.ErrorResponse{{HttpStatus: jsii.Number(403), Ttl: awscdk.Duration_Seconds(jsii.Number(0))}, {HttpStatus: jsii.Number(404), Ttl: awscdk.Duration_Seconds(jsii.Number(0))}}})
	awsroute53.NewCfnRecordSet(stack, jsii.String("PublicDomain"), &awsroute53.CfnRecordSetProps{HostedZoneId: jsii.String(hostedZoneID()), Name: jsii.String(domain), Type: jsii.String("A"), AliasTarget: &awsroute53.CfnRecordSet_AliasTargetProperty{DnsName: distribution.DistributionDomainName(), HostedZoneId: jsii.String("Z2FDTNDATAQYW2"), EvaluateTargetHealth: jsii.Bool(false)}})
	for name, value := range map[string]*string{"CloudFrontDistributionId": distribution.DistributionId(), "CloudFrontDomain": distribution.DistributionDomainName(), "EdgeWebAclArn": webACL, "StaticSiteBucketName": bucket.BucketName()} {
		awscdk.NewCfnOutput(stack, jsii.String(name), &awscdk.CfnOutputProps{Value: value})
	}
	return distribution
}

func staticSiteManagementStatement(account, region string) awsiam.PolicyStatement {
	// CloudFormation reads bucket properties beyond those explicitly set in
	// the template during stabilization/drift checks. Permit metadata reads
	// on this bucket only; never object reads or deletion.
	return staticSiteBucketPermissions(account, region, []string{"s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketLocation", "s3:GetAccelerateConfiguration", "s3:GetLifecycleConfiguration", "s3:GetBucketPublicAccessBlock", "s3:GetAnalyticsConfiguration", "s3:GetBucketCORS", "s3:GetEncryptionConfiguration", "s3:GetInventoryConfiguration", "s3:GetBucketLogging", "s3:GetMetricsConfiguration", "s3:GetBucketNotification", "s3:GetBucketVersioning", "s3:GetReplicationConfiguration", "s3:GetBucketWebsite", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketTagging", "s3:ListTagsForResource", "s3:GetBucketAbac", "s3:GetBucketOwnershipControls", "s3:GetIntelligentTieringConfiguration", "s3:GetBucketMetadataTableConfiguration", "s3:ListBucket"})
}

func staticSiteBoundaryStatement(account, region string) awsiam.PolicyStatement {
	// Keep the protected ceiling compact. The identity policy above lists
	// exact metadata reads; this bucket ARN cannot authorize object access.
	return staticSiteBucketPermissions(account, region, []string{"s3:GetBucket*", "s3:Get*Configuration", "s3:ListBucket", "s3:ListTagsForResource"})
}

func staticSiteBucketPermissions(account, region string, reads []string) awsiam.PolicyStatement {
	actions := append([]string{"s3:CreateBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls", "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning", "s3:PutBucketTagging"}, reads...)
	return allow(jsii.Strings(actions...), jsii.Strings("arn:aws:s3:::"+staticSiteBucketName(account, region)))
}

// Avoid embedding the operator's account ID in an origin bucket name that S3
// might return in an error response. This is opaque naming, not a secret.
func staticSiteBucketName(account, region string) string {
	sum := sha256.Sum256([]byte("agent-pdf-site:" + account + ":" + region))
	return "agent-pdf-site-" + hex.EncodeToString(sum[:8]) + "-" + region
}
