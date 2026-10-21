package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsevents"
	"github.com/aws/aws-cdk-go/awscdk/v2/awseventstargets"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	"github.com/aws/jsii-runtime-go"
)

const htmlAPIPath = "/v1/html/markdown"

func htmlEnabled() bool {
	switch os.Getenv("PDF_ENABLE_HTML") {
	case "", "0":
		return false
	case "1":
		return true
	default:
		panic("PDF_ENABLE_HTML must be 0 or 1")
	}
}

// HTML has an independent cutover so enabling it for owner testing cannot
// expose an untested route alongside the already-public PDF service.
func htmlPublicAccess() bool {
	switch os.Getenv("PDF_HTML_PUBLIC_ACCESS") {
	case "", "0":
		return false
	case "1":
		if !htmlEnabled() || !htmlJavaScript() || !publicAccessSetting(os.Getenv("PDF_PUBLIC_ACCESS"), os.Getenv("PDF_PAYMENT_MODE")) {
			panic("public HTML requires enabled disposable-browser processing and public Base payments")
		}
		return true
	default:
		panic("PDF_HTML_PUBLIC_ACCESS must be 0 or 1")
	}
}

// This prepares an experimental image; it is never an ordinary-deploy default.
// Confirm Chromium namespace/seccomp support in Lambda before release.
func htmlJavaScript() bool {
	switch os.Getenv("PDF_HTML_JAVASCRIPT") {
	case "", "0":
		return false
	case "1":
		if !htmlEnabled() {
			panic("JavaScript requires HTML")
		}
		return true
	default:
		panic("PDF_HTML_JAVASCRIPT must be 0 or 1")
	}
}
func threatBucketName(account string) string {
	sum := sha256.Sum256([]byte("agent-pdf-html-threats:" + account))
	return "utils-bot-threats-" + hex.EncodeToString(sum[:8])
}

// The worker has no payment, SSM, DynamoDB or Invoke authority. A fresh tenant
// per synchronous job prevents Lambda reusing its environment across requests.
// Only public threat data is written to S3; fetched HTML/results never are.
func htmlFunctions(stack awscdk.Stack, payment awslambda.IAlias, cfg paymentConfig) awslambda.Function {
	var bucket awss3.IBucket
	if os.Getenv("PDF_HTML_REUSE_THREATS") == "1" {
		if !htmlEnabled() {
			panic("retained threat import requires explicit HTML enablement")
		}
		bucket = awss3.Bucket_FromBucketAttributes(stack, jsii.String("RetainedHtmlThreatData"), &awss3.BucketAttributes{BucketName: jsii.String(threatBucketName(*stack.Account()))})
		// Its retained TLS-only policy already exists. A second CloudFormation
		// owner fails creation; deleting/replacing it weakens the boundary.
		// The private prepare workflow verifies owner, TLS deny and public-access
		// controls before selecting this explicitly imported bucket.
	} else {
		bucket = awss3.NewBucket(stack, jsii.String("HtmlThreatData"), &awss3.BucketProps{
			BucketName: jsii.String(threatBucketName(*stack.Account())), BlockPublicAccess: awss3.BlockPublicAccess_BLOCK_ALL(),
			Encryption: awss3.BucketEncryption_S3_MANAGED, EnforceSSL: jsii.Bool(true), ObjectOwnership: awss3.ObjectOwnership_BUCKET_OWNER_ENFORCED,
			LifecycleRules: &[]*awss3.LifecycleRule{{Prefix: jsii.String("threats/v2/generations/"), Expiration: awscdk.Duration_Days(jsii.Number(3)), AbortIncompleteMultipartUploadAfter: awscdk.Duration_Days(jsii.Number(1))}},
			Versioned:      jsii.Bool(false), RemovalPolicy: awscdk.RemovalPolicy_RETAIN,
		})
	}
	makeFunction := func(id, name, asset string, memory, timeout, concurrency float64, env map[string]*string, isolate bool) awslambda.Function {
		logs := awslogs.NewLogGroup(stack, jsii.String(id+"Logs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/" + name), Retention: awslogs.RetentionDays_ONE_WEEK, RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
		role := awsiam.NewRole(stack, jsii.String(id+"Role"), &awsiam.RoleProps{AssumedBy: awsiam.NewServicePrincipal(jsii.String("lambda.amazonaws.com"), nil)})
		logs.GrantWrite(role)
		props := &awslambda.FunctionProps{FunctionName: jsii.String("agent-pdf-" + name), Role: role, Runtime: awslambda.Runtime_PROVIDED_AL2023(), Architecture: awslambda.Architecture_ARM_64(), Handler: jsii.String("bootstrap"), Code: awslambda.Code_FromAsset(jsii.String("../build/"+asset), nil), MemorySize: jsii.Number(memory), Timeout: awscdk.Duration_Seconds(jsii.Number(timeout)), ReservedConcurrentExecutions: jsii.Number(concurrency), LogGroup: logs, Environment: &env, Tracing: awslambda.Tracing_DISABLED}
		if isolate {
			props.TenancyConfig = awslambda.TenancyConfig_PER_TENANT()
		}
		return awslambda.NewFunction(stack, jsii.String(id), props)
	}
	env := map[string]*string{"PAYMENT_MODE": jsii.String(cfg.Mode), "PAYMENT_PAY_TO": jsii.String(cfg.PayTo), "RESOURCE_URL": jsii.String("https://" + regionalAPIHost + htmlAPIPath), "PAYMENT_FUNCTION_ARN": payment.FunctionArn(), "HTML_JAVASCRIPT": jsii.String("0")}
	var image awslambda.CfnMicrovmImage
	var workerAlias awslambda.Alias
	if htmlJavaScript() {
		image = htmlMicroVMImage(stack, *bucket.BucketName(), false)
		env["HTML_JAVASCRIPT"] = jsii.String("1")
		env["MICROVM_IMAGE_ARN"] = image.AttrImageArn()
		env["MICROVM_IMAGE_VERSION"] = image.AttrLatestActiveImageVersion()
		env["THREAT_BUCKET"] = bucket.BucketName()
	} else {
		worker := makeFunction("HtmlWorker", "html-worker", "html-worker", 256, 25, 8, map[string]*string{"THREAT_BUCKET": bucket.BucketName(), "GOMEMLIMIT": jsii.String("192MiB")}, true)
		worker.AddToRolePolicy(allow(jsii.Strings("s3:GetObject"), jsii.Strings(*bucket.BucketArn()+"/threats/v2/current.json", *bucket.BucketArn()+"/threats/v2/generations/*")))
		workerAlias = awslambda.NewAlias(stack, jsii.String("HtmlWorkerAlias"), &awslambda.AliasProps{AliasName: jsii.String("live"), Version: worker.CurrentVersion()})
		env["WORKER_FUNCTION_ARN"] = workerAlias.FunctionArn()
	}
	controller := makeFunction("HtmlController", "html", "html", 256, 80, 8, env, false)
	payment.GrantInvoke(controller)
	if image != nil {
		controller.AddToRolePolicy(allow(jsii.Strings("lambda:RunMicrovm", "lambda:GetMicrovm", "lambda:TerminateMicrovm", "lambda:CreateMicrovmAuthToken"), jsii.Strings(*image.AttrImageArn())))
		controller.AddToRolePolicy(allow(jsii.Strings("lambda:PassNetworkConnector"), jsii.Strings("arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:INTERNET_EGRESS", "arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:ALL_INGRESS")))
		controller.AddToRolePolicy(allow(jsii.Strings("s3:GetObject"), jsii.Strings(*bucket.BucketArn()+"/threats/v2/*")))
	} else {
		workerAlias.GrantInvoke(controller)
	}

	updater := makeFunction("HtmlThreatUpdater", "html-threat-update", "threat-update", 1536, 180, 1, map[string]*string{"THREAT_BUCKET": bucket.BucketName(), "GOMEMLIMIT": jsii.String("1200MiB")}, false)
	updater.AddToRolePolicy(allow(jsii.Strings("s3:PutObject"), jsii.Strings(*bucket.BucketArn()+"/threats/v2/current.json", *bucket.BucketArn()+"/threats/v2/generations/*")))
	refreshInterval := awscdk.Duration_Hours(jsii.Number(1))
	if os.Getenv("PDF_HTML_INTEGRATION_ONLY") == "1" {
		refreshInterval = awscdk.Duration_Minutes(jsii.Number(5))
	}
	awsevents.NewRule(stack, jsii.String("HtmlThreatRefresh"), &awsevents.RuleProps{RuleName: jsii.String("agent-pdf-html-threat-refresh"), Schedule: awsevents.Schedule_Rate(refreshInterval), Targets: &[]awsevents.IRuleTarget{awseventstargets.NewLambdaFunction(updater, &awseventstargets.LambdaFunctionProps{RetryAttempts: jsii.Number(1), MaxEventAge: awscdk.Duration_Minutes(jsii.Number(10))})}})
	awscdk.NewCfnOutput(stack, jsii.String("HtmlControllerArn"), &awscdk.CfnOutputProps{Value: controller.FunctionArn()})
	awscdk.NewCfnOutput(stack, jsii.String("HtmlThreatUpdaterName"), &awscdk.CfnOutputProps{Value: updater.FunctionName()})
	// Invoke updater once during deliberate deployment validation; until that
	// succeeds the worker fails closed and no customer payment is collected.
	return controller
}

func htmlDeploymentStatements(account, region string) []awsiam.PolicyStatement {
	return []awsiam.PolicyStatement{
		allow(jsii.Strings("elasticloadbalancing:CreateTargetGroup", "elasticloadbalancing:DeleteTargetGroup", "elasticloadbalancing:ModifyTargetGroupAttributes", "elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets", "elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"), jsii.Strings("arn:aws:elasticloadbalancing:"+region+":"+account+":targetgroup/agent-pdf-mock-html-test/*", "arn:aws:elasticloadbalancing:"+region+":"+account+":targetgroup/agent-pdf-mock-html/*")),
		allow(jsii.Strings("elasticloadbalancing:CreateRule", "elasticloadbalancing:DeleteRule", "elasticloadbalancing:ModifyRule", "elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"), jsii.Strings("arn:aws:elasticloadbalancing:"+region+":"+account+":listener/app/agent-pdf-mock/*", "arn:aws:elasticloadbalancing:"+region+":"+account+":listener-rule/app/agent-pdf-mock/*")),
		allow(jsii.Strings("dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:DescribeTable", "dynamodb:DescribeTimeToLive", "dynamodb:UpdateTimeToLive", "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:ListTagsOfResource"), jsii.Strings("arn:aws:dynamodb:"+region+":"+account+":table/agent-pdf-html-test-payments")),
		// AWS does not support an image ARN for CreateMicrovmImage. Constrain
		// creation by project request tag and region instead; subsequent image
		// operations remain scoped to this application's exact name prefix.
		// PaymentMode is an inherited main-stack tag; omitting it rejects creation.
		allow(jsii.Strings("lambda:CreateMicrovmImage", "lambda:TagResource"), jsii.Strings("*"), &map[string]interface{}{"StringEquals": map[string]any{"aws:RequestedRegion": region, "aws:RequestTag/Project": "agent-pdf"}, "ForAllValues:StringEquals": map[string]any{"aws:TagKeys": []string{"Project", "PaymentMode"}}}),
		allow(jsii.Strings("lambda:UpdateMicrovmImage", "lambda:DeleteMicrovmImage", "lambda:GetMicrovmImage", "lambda:GetMicrovmImageVersion", "lambda:DeleteMicrovmImageVersion", "lambda:TagResource", "lambda:TagResource20170331v2", "lambda:UntagResource", "lambda:UntagResource20170331v2", "lambda:ListTags"), jsii.Strings("arn:aws:lambda:"+region+":"+account+":microvm-image:agent-pdf-html*")),
		allow(jsii.Strings("lambda:PassNetworkConnector"), jsii.Strings("arn:aws:lambda:"+region+":aws:network-connector:aws-network-connector:INTERNET_EGRESS")),
		allow(jsii.Strings("lambda:CreateFunction", "lambda:GetFunction*", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy", "lambda:UpdateFunction*", "lambda:DeleteFunction", "lambda:ListVersionsByFunction", "lambda:ListTags", "lambda:TagResource", "lambda:UntagResource", "lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency", "lambda:GetFunctionConcurrency", "lambda:PublishVersion", "lambda:CreateAlias", "lambda:UpdateAlias", "lambda:DeleteAlias", "lambda:GetAlias", "lambda:ListAliases", "lambda:AddPermission", "lambda:RemovePermission"), jsii.Strings("arn:aws:lambda:"+region+":"+account+":function:agent-pdf-html*")),
		allow(jsii.Strings("events:PutRule", "events:DescribeRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets", "events:ListTargetsByRule", "events:TagResource", "events:UntagResource", "events:ListTagsForResource"), jsii.Strings("arn:aws:events:"+region+":"+account+":rule/agent-pdf-html-threat-refresh")),
		allow(jsii.Strings("s3:CreateBucket", "s3:GetBucket*", "s3:Get*Configuration", "s3:ListBucket", "s3:ListTagsForResource", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls", "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning", "s3:PutBucketTagging", "s3:PutLifecycleConfiguration"), jsii.Strings("arn:aws:s3:::"+threatBucketName(account))),
	}
}
