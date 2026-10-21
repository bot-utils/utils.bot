package main

import (
	"os"
	"regexp"
	"strconv"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3assets"
	"github.com/aws/jsii-runtime-go"
)

// htmlMicroVMMemory supports bounded private right-sizing experiments. Never
// silently accept an arbitrary resource value from deployment configuration.
func htmlMicroVMMemory(raw string) int {
	if raw == "" {
		return 512
	}
	value, err := strconv.Atoi(raw)
	if err != nil || (value != 512 && value != 1024 && value != 2048) {
		panic("PDF_HTML_VM_MEMORY_MIB must be 512, 1024 or 2048")
	}
	return value
}

func htmlMicroVMImage(stack awscdk.Stack, bucket string, probe bool) awslambda.CfnMicrovmImage {
	if info, err := os.Stat("../build/html-microvm-image/runtime.tar"); err != nil || !info.Mode().IsRegular() {
		panic("stage the frozen HTML runtime before synthesis")
	}
	version := os.Getenv("PDF_MICROVM_BASE_VERSION")
	if !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`).MatchString(version) {
		panic("set PDF_MICROVM_BASE_VERSION to a reviewed managed base image version")
	}
	name := "agent-pdf-html-browser"
	if probe {
		name = "agent-pdf-html-probe"
	}
	// Ship the exact locally inspected filesystem. AWS does no package downloads.
	asset := awss3assets.NewAsset(stack, jsii.String("MicroVMSource"), &awss3assets.AssetProps{Path: jsii.String("../build/html-microvm-image"), Exclude: jsii.Strings("**", "!Dockerfile", "!runtime.tar"), IgnoreMode: awscdk.IgnoreMode_DOCKER})
	roleName := "AgentPdfMock-html-microvm-build"
	if probe {
		roleName += "-probe"
	}
	role := awsiam.NewRole(stack, jsii.String("MicroVMBuildRole"), &awsiam.RoleProps{RoleName: jsii.String(roleName), AssumedBy: awsiam.NewServicePrincipal(jsii.String("lambda.amazonaws.com"), nil)})
	role.AssumeRolePolicy().AddStatements(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: jsii.Strings("sts:TagSession"), Principals: &[]awsiam.IPrincipal{awsiam.NewServicePrincipal(jsii.String("lambda.amazonaws.com"), nil)}}))
	role.AddToPolicy(allow(jsii.Strings("s3:GetObject"), jsii.Strings(*asset.Bucket().ArnForObjects(asset.S3ObjectKey()))))
	logs := awslogs.NewLogGroup(stack, jsii.String("MicroVMBuildLogs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/" + name + "-build"), Retention: awslogs.RetentionDays_ONE_WEEK, RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
	logs.GrantWrite(role)
	environment := []*awslambda.CfnMicrovmImage_EnvironmentVariableProperty{{Key: jsii.String("THREAT_BUCKET"), Value: jsii.String(bucket)}, {Key: jsii.String("GOMEMLIMIT"), Value: jsii.String("256MiB")}}
	if probe {
		environment = append(environment, &awslambda.CfnMicrovmImage_EnvironmentVariableProperty{Key: jsii.String("MICROVM_PROBE"), Value: jsii.String("1")})
	}
	image := awslambda.NewCfnMicrovmImage(stack, jsii.String("BrowserImage"), &awslambda.CfnMicrovmImageProps{
		Name: jsii.String(name), Description: jsii.String("One credential-free browser job per disposable MicroVM"),
		Tags:         &[]*awscdk.CfnTag{{Key: jsii.String("Project"), Value: jsii.String("agent-pdf")}},
		BaseImageArn: jsii.String("arn:aws:lambda:us-east-2:aws:microvm-image:al2023-1"), BaseImageVersion: jsii.String(version), BuildRoleArn: role.RoleArn(),
		CodeArtifact:             &awslambda.CfnMicrovmImage_CodeArtifactProperty{Uri: asset.S3ObjectUrl()},
		AdditionalOsCapabilities: jsii.Strings(), CpuConfigurations: []*awslambda.CfnMicrovmImage_CpuConfigurationProperty{{Architecture: jsii.String("ARM_64")}},
		Resources: []*awslambda.CfnMicrovmImage_ResourcesProperty{{MinimumMemoryInMiB: jsii.Number(float64(htmlMicroVMMemory(os.Getenv("PDF_HTML_VM_MEMORY_MIB"))))}}, EnvironmentVariables: environment,
		EgressNetworkConnectors: jsii.Strings("arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:INTERNET_EGRESS"),
		Hooks:                   &awslambda.CfnMicrovmImage_HooksProperty{Port: jsii.Number(8080), MicrovmImageHooks: &awslambda.CfnMicrovmImage_MicrovmImageHooksProperty{Ready: jsii.String("ENABLED"), ReadyTimeoutInSeconds: jsii.Number(30), Validate: jsii.String("ENABLED"), ValidateTimeoutInSeconds: jsii.Number(30)}},
		Logging:                 &awslambda.CfnMicrovmImage_LoggingProperty{CloudWatch: &awslambda.CfnMicrovmImage_CloudWatchLoggingProperty{LogGroup: logs.LogGroupName()}},
	})
	image.Node().AddDependency(role.Node().FindChild(jsii.String("DefaultPolicy")))
	awscdk.NewCfnOutput(stack, jsii.String("MicroVMImageArn"), &awscdk.CfnOutputProps{Value: image.AttrImageArn()})
	awscdk.NewCfnOutput(stack, jsii.String("MicroVMImageVersion"), &awscdk.CfnOutputProps{Value: image.AttrLatestActiveImageVersion()})
	return image
}

func microVMProbeStack(app awscdk.App, account, region string) awscdk.Stack {
	if !dedicatedExecutionSetting(os.Getenv("PDF_USE_DEDICATED_EXECUTION_ROLE")) {
		panic("MicroVM probe requires bounded deployment")
	}
	stack := awscdk.NewStack(app, jsii.String("AgentPdfMock-MicroVMProbe"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)}, Synthesizer: pdfStackSynthesizer(account)})
	applyRuntimeBoundary(stack, account, false)
	htmlMicroVMImage(stack, "synthetic-threat-fixture", true)
	return stack
}
