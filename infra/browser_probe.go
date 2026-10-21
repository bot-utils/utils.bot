package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecrassets"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/jsii-runtime-go"
	"os"
)

// The probe is an independent, temporary stack. No ALB route, public URL,
// schedule, payment/SSM/table/bucket access or always-on capacity is created.
func browserProbeStack(app awscdk.App, account, region string) awscdk.Stack {
	if !dedicatedExecutionSetting(os.Getenv("PDF_USE_DEDICATED_EXECUTION_ROLE")) {
		panic("private browser probe requires bounded deployment")
	}
	stack := awscdk.NewStack(app, jsii.String("AgentPdfMock-BrowserProbe"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)}, Synthesizer: pdfStackSynthesizer(account), Description: jsii.String("Private synthetic browser isolation and startup test")})
	applyRuntimeBoundary(stack, account, false)
	logs := awslogs.NewLogGroup(stack, jsii.String("Logs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/browser-probe"), Retention: awslogs.RetentionDays_ONE_WEEK, RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
	role := awsiam.NewRole(stack, jsii.String("Role"), &awsiam.RoleProps{RoleName: jsii.String("AgentPdfMock-browser-probe"), AssumedBy: awsiam.NewServicePrincipal(jsii.String("lambda.amazonaws.com"), nil)})
	logs.GrantWrite(role)
	function := awslambda.NewFunction(stack, jsii.String("Probe"), &awslambda.FunctionProps{FunctionName: jsii.String("agent-pdf-html-browser-probe"), Role: role, Runtime: awslambda.Runtime_FROM_IMAGE(), Handler: awslambda.Handler_FROM_IMAGE(), Architecture: awslambda.Architecture_ARM_64(), Code: awslambda.Code_FromAssetImage(jsii.String(".."), &awslambda.AssetImageCodeProps{File: jsii.String("Dockerfile.browser"), Target: jsii.String("probe"), Platform: awsecrassets.Platform_LINUX_ARM64(), Exclude: jsii.Strings("**", "!native", "native/**", "!native/browser-launch.c", "!build", "build/**", "!build/browser-probe", "build/browser-probe/**", "!build/browser-probe/bootstrap", "!Dockerfile.browser", "!Dockerfile.browser.dockerignore"), IgnoreMode: awscdk.IgnoreMode_DOCKER}), MemorySize: jsii.Number(2048), Timeout: awscdk.Duration_Seconds(jsii.Number(20)), ReservedConcurrentExecutions: jsii.Number(2), TenancyConfig: awslambda.TenancyConfig_PER_TENANT(), LogGroup: logs, Environment: &map[string]*string{"GOMEMLIMIT": jsii.String("256MiB")}, Tracing: awslambda.Tracing_DISABLED})
	awscdk.NewCfnOutput(stack, jsii.String("ProbeFunctionName"), &awscdk.CfnOutputProps{Value: function.FunctionName()})
	return stack
}
