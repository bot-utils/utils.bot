package main

import (
	"fmt"
	"net"
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecrassets"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/jsii-runtime-go"
)

func main() {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	account := os.Getenv("CDK_DEFAULT_ACCOUNT")
	requireDeploymentAccount(account, os.Getenv("PDF_LOCALSTACK") == "1")
	if os.Getenv("PDF_CLOUDFRONT_ACCESS_LOGS_ONLY") == "1" {
		cloudFrontAccessLogsStack(app, account, os.Getenv("PDF_CLOUDFRONT_DISTRIBUTION_ID"))
		app.Synth(nil)
		return
	}
	region := os.Getenv("CDK_DEFAULT_REGION")
	if region == "" {
		region = "us-east-2"
	}
	if region != "us-east-2" {
		panic("this test stack is restricted to us-east-2")
	}
	local := os.Getenv("PDF_LOCALSTACK") == "1"
	if local && account != "000000000000" {
		panic("LocalStack synthesis requires the dummy account")
	}
	if local {
		app.Node().SetContext(jsii.String("availability-zones:account=000000000000:region=us-east-2"), []string{"us-east-2a", "us-east-2b"})
	}
	if local && os.Getenv("PDF_LOCAL_ASSETS_ONLY") == "1" {
		localAssets(app)
		app.Synth(nil)
		return
	}
	if os.Getenv("PDF_FOUNDATION_ONLY") == "1" {
		if local {
			panic("the production IAM foundation cannot be deployed to LocalStack")
		}
		foundationStack(app, account, region)
		app.Synth(nil)
		return
	}
	if os.Getenv("PDF_BUDGET_ONLY") == "1" {
		stack := awscdk.NewStack(app, jsii.String("AgentPdfBudgets"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)}, Description: jsii.String("Monthly account-wide Fargate spending notifications"), Synthesizer: pdfStackSynthesizer(account)})
		fargateBudget(stack)
		app.Synth(nil)
		return
	}
	if os.Getenv("PDF_AUDIT_ONLY") == "1" {
		auditTrailStack(app, account, region, local)
		app.Synth(nil)
		return
	}
	if os.Getenv("PDF_EDGE_PREP_ONLY") == "1" {
		edgePrerequisites(app, account)
		app.Synth(nil)
		return
	}
	if os.Getenv("PDF_HTML_INTEGRATION_ONLY") == "1" {
		if local {
			panic("HTML integration requires real AWS")
		}
		htmlIntegrationStack(app, account, region)
		app.Synth(nil)
		return
	}
	if os.Getenv("PDF_MICROVM_PROBE_ONLY") == "1" {
		if local {
			panic("MicroVM compatibility requires real AWS")
		}
		microVMProbeStack(app, account, region)
		app.Synth(nil)
		return
	}
	if os.Getenv("PDF_BROWSER_PROBE_ONLY") == "1" {
		if local {
			panic("browser capability tests require real Lambda")
		}
		browserProbeStack(app, account, region)
		app.Synth(nil)
		return
	}
	edgeEnabled := os.Getenv("PDF_ENABLE_EDGE") == "1"
	directAPI := directAPIEnabled()
	if htmlEnabled() && !directAPI {
		panic("HTML requires protected regional API ingress")
	}
	if htmlEnabled() && htmlJavaScript() && !local {
		if err := requireHTMLNativeReview("../native/browser-advisories.json"); err != nil {
			panic(err)
		}
		if err := requireHTMLRuntimeArtifact(); err != nil {
			panic(err)
		}
	}
	staticSite := staticSiteEnabled()
	if directAPI && !edgeEnabled {
		panic("regional API requires the protected website/origin configuration")
	}
	paymentCfg := deploymentPaymentConfig(os.Getenv("PDF_PAYMENT_MODE"), os.Getenv("PDF_PAYMENT_PAY_TO"), local, edgeEnabled)
	public := publicAccessSetting(os.Getenv("PDF_PUBLIC_ACCESS"), paymentCfg.Mode)
	if public && !edgeEnabled {
		panic("public access requires the protected HTTPS edge")
	}
	cidr := os.Getenv("PDF_ALLOWED_CIDR")
	if !ownerCIDR(cidr) {
		panic("set PDF_ALLOWED_CIDR to the testing client's public IPv4 /32")
	}
	stackName := "AgentPdfMock"
	if local {
		stackName = "AgentPdfLocal"
	}
	stack := awscdk.NewStack(app, jsii.String(stackName), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)}, Description: jsii.String("Private PDF parser with explicit payment configuration"), TerminationProtection: stackTerminationProtection(local), Synthesizer: pdfStackSynthesizer(account)})
	awscdk.Tags_Of(stack).Add(jsii.String("Project"), jsii.String("agent-pdf"), nil)
	applyRuntimeBoundary(stack, account, local)
	awscdk.Tags_Of(stack).Add(jsii.String("PaymentMode"), jsii.String(paymentCfg.Mode), nil)
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0), SubnetConfiguration: &[]*awsec2.SubnetConfiguration{{Name: jsii.String("public"), SubnetType: awsec2.SubnetType_PUBLIC, CidrMask: jsii.Number(24)}}})
	prefix := ""
	if edgeEnabled {
		prefix = requiredEdgeValue("PDF_CLOUDFRONT_PREFIX_LIST", "pl-")
	}
	albSG, taskSG, originSG := networkSecurity(stack, vpc, cidr, prefix)
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc, LoadBalancerName: jsii.String("agent-pdf-mock"), InternetFacing: jsii.Bool(true), SecurityGroup: albSG, IdleTimeout: awscdk.Duration_Seconds(jsii.Number(120))})
	if originSG != nil {
		alb.AddSecurityGroup(originSG)
	}
	hardenALB(alb, !local)
	resource := awscdk.Fn_Join(jsii.String(""), &[]*string{jsii.String("http://"), alb.LoadBalancerDnsName(), jsii.String("/v1/pdf/text")})
	health := awscdk.Fn_Join(jsii.String(""), &[]*string{jsii.String("http://"), alb.LoadBalancerDnsName(), jsii.String("/health")})
	if edgeEnabled {
		resource = jsii.String("https://" + domain + "/v1/pdf/text")
		if directAPI {
			resource = jsii.String("https://" + regionalAPIHost + "/v1/pdf/text")
		}
		health = jsii.String("https://" + domain + "/health")
	}
	originToken, originCert := edgeOrigin(stack, alb, edgeEnabled)
	table := paymentBindings(stack)
	paymentLogs := awslogs.NewLogGroup(stack, jsii.String("PaymentLogs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/payment"), Retention: awslogs.RetentionDays_ONE_WEEK, RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
	payment := awslambda.NewFunction(stack, jsii.String("Payment"), &awslambda.FunctionProps{FunctionName: jsii.String("agent-pdf-mock-payment"), Runtime: awslambda.Runtime_PROVIDED_AL2023(), Architecture: awslambda.Architecture_ARM_64(), Handler: jsii.String("bootstrap"), Code: awslambda.Code_FromAsset(jsii.String("../build/payment"), nil), MemorySize: jsii.Number(256), Timeout: awscdk.Duration_Seconds(jsii.Number(20)), ReservedConcurrentExecutions: jsii.Number(paymentReservedConcurrency), LogGroup: paymentLogs, Environment: &map[string]*string{"PAYMENT_MODE": jsii.String(paymentCfg.Mode), "PAYMENT_PAY_TO": jsii.String(paymentCfg.PayTo), "PAYMENT_TABLE": table.TableName(), "RESOURCE_URL": resource}})
	payment.AddToRolePolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: &[]*string{jsii.String("dynamodb:GetItem"), jsii.String("dynamodb:PutItem"), jsii.String("dynamodb:UpdateItem")}, Resources: &[]*string{table.TableArn()}}))
	coinbaseParameters(stack, payment, os.Getenv("PDF_ENABLE_CDP_CHECK") == "1" || paymentCfg.Mode != "mock")
	if htmlEnabled() {
		payment.AddEnvironment(jsii.String("HTML_RESOURCE_URL"), jsii.String("https://"+regionalAPIHost+htmlAPIPath), nil)
	}
	alias := awslambda.NewAlias(stack, jsii.String("PaymentAlias"), &awslambda.AliasProps{AliasName: jsii.String("live"), Version: payment.CurrentVersion()})
	cluster := awsecs.NewCluster(stack, jsii.String("Cluster"), &awsecs.ClusterProps{Vpc: vpc, ClusterName: jsii.String("agent-pdf-mock")})
	task := awsecs.NewFargateTaskDefinition(stack, jsii.String("Task"), &awsecs.FargateTaskDefinitionProps{Family: jsii.String("agent-pdf-mock"), Cpu: jsii.Number(256), MemoryLimitMiB: jsii.Number(2048), RuntimePlatform: &awsecs.RuntimePlatform{CpuArchitecture: awsecs.CpuArchitecture_ARM64(), OperatingSystemFamily: awsecs.OperatingSystemFamily_LINUX()}})
	alias.GrantInvoke(task.TaskRole())
	logs := awslogs.NewLogGroup(stack, jsii.String("ServerLogs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/server"), Retention: awslogs.RetentionDays_ONE_WEEK, RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
	linux := awsecs.NewLinuxParameters(stack, jsii.String("Linux"), &awsecs.LinuxParametersProps{InitProcessEnabled: jsii.Bool(true)})
	linux.DropCapabilities(awsecs.Capability_ALL)
	imageTarget := serverImageTarget(os.Getenv("PDF_PRIVATE_EDGE_CHECK"), account, local, edgeEnabled, public)
	task.AddContainer(jsii.String("Server"), &awsecs.ContainerDefinitionOptions{Image: awsecs.ContainerImage_FromAsset(jsii.String(".."), &awsecs.AssetImageProps{Platform: awsecrassets.Platform_LINUX_ARM64(), Target: jsii.String(imageTarget)}), User: jsii.String("10001:10001"), ReadonlyRootFilesystem: jsii.Bool(true), LinuxParameters: linux, StopTimeout: awscdk.Duration_Seconds(jsii.Number(120)), Logging: awsecs.LogDriver_AwsLogs(&awsecs.AwsLogDriverProps{StreamPrefix: jsii.String("server"), LogGroup: logs}), Environment: &map[string]*string{"PAYMENT_MODE": jsii.String(paymentCfg.Mode), "PAYMENT_PAY_TO": jsii.String(paymentCfg.PayTo), "RESOURCE_URL": resource, "PAYMENT_FUNCTION_ARN": alias.FunctionArn(), "PUBLIC_ACCESS": jsii.String(boolSetting(public)), "GOMEMLIMIT": jsii.String("512MiB")}, PortMappings: &[]*awsecs.PortMapping{{ContainerPort: jsii.Number(8080), Protocol: awsecs.Protocol_TCP}}})
	hardenTaskRoles(task)
	autoscaling := autoscalingSetting(os.Getenv("PDF_ENABLE_AUTOSCALING"), os.Getenv("PDF_DESIRED_COUNT"))
	autoscalingConfigured := autoscalingConfiguredSetting(os.Getenv("PDF_AUTOSCALING_CONFIGURED"))
	serviceProps := boundedServiceDeployment(public)
	serviceProps.ServiceName = jsii.String("agent-pdf-mock")
	serviceProps.Cluster = cluster
	serviceProps.TaskDefinition = task
	serviceProps.DesiredCount = serviceDesiredCount(os.Getenv("PDF_DESIRED_COUNT"), autoscaling)
	serviceProps.AssignPublicIp = jsii.Bool(true)
	serviceProps.SecurityGroups = &[]awsec2.ISecurityGroup{taskSG}
	serviceProps.VpcSubnets = &awsec2.SubnetSelection{SubnetType: awsec2.SubnetType_PUBLIC}
	serviceProps.HealthCheckGracePeriod = awscdk.Duration_Seconds(jsii.Number(60))
	serviceProps.CircuitBreaker = &awsecs.DeploymentCircuitBreaker{Rollback: jsii.Bool(true)}
	service := awsecs.NewFargateService(stack, jsii.String("Service"), serviceProps)
	service.Node().AddDependency(alias)
	listener, conditions := backendListener(alb, edgeEnabled, originToken, originCert)
	targets := listener.AddTargets(jsii.String("Api"), &awselasticloadbalancingv2.AddApplicationTargetsProps{TargetGroupName: jsii.String("agent-pdf-mock"), Priority: jsii.Number(10), Conditions: &conditions, Port: jsii.Number(8080), Protocol: awselasticloadbalancingv2.ApplicationProtocol_HTTP, Targets: &[]awselasticloadbalancingv2.IApplicationLoadBalancerTarget{service}, DeregistrationDelay: awscdk.Duration_Seconds(jsii.Number(120)), HealthCheck: &awselasticloadbalancingv2.HealthCheck{Path: jsii.String("/health"), Interval: awscdk.Duration_Seconds(jsii.Number(10)), Timeout: awscdk.Duration_Seconds(jsii.Number(5)), HealthyThresholdCount: jsii.Number(2)}})
	balanceBusyParsers(targets)
	if directAPI {
		if htmlEnabled() {
			regionalAPI(stack, alb, targets, listener, htmlFunctions(stack, alias, paymentCfg))
		} else {
			regionalAPI(stack, alb, targets, listener)
		}
	}
	if autoscaling {
		configureServiceAutoscaling(service, targets)
	}
	if edgeEnabled {
		operationalAlarms(stack, alb, targets, service, payment)
	} else if os.Getenv("PDF_ENABLE_GUARDRAILS") == "1" {
		guardrails(stack, alb, targets, service, payment)
	}
	awscdk.NewCfnOutput(stack, jsii.String("StaticSiteEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(staticSite))})
	awscdk.NewCfnOutput(stack, jsii.String("RegionalApiEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(directAPI))})
	awscdk.NewCfnOutput(stack, jsii.String("PublicAccessEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(public))})
	awscdk.NewCfnOutput(stack, jsii.String("HTMLEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(htmlEnabled()))})
	awscdk.NewCfnOutput(stack, jsii.String("HTMLJavaScriptEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(htmlJavaScript()))})
	awscdk.NewCfnOutput(stack, jsii.String("HTMLPublicAccessEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(htmlPublicAccess()))})
	awscdk.NewCfnOutput(stack, jsii.String("HTMLThreatBucketImported"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(htmlEnabled() && os.Getenv("PDF_HTML_REUSE_THREATS") == "1"))})
	awscdk.NewCfnOutput(stack, jsii.String("OperationalMonitoringEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(monitoringSetting(os.Getenv("PDF_ENABLE_OPERATIONAL_ALARMS")))})
	awscdk.NewCfnOutput(stack, jsii.String("AutoscalingEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(autoscaling))})
	awscdk.NewCfnOutput(stack, jsii.String("AutoscalingConfigured"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(autoscalingConfigured))})
	if !local && os.Getenv("PDF_ENABLE_MONITORING") == "1" && monitoringSetting(os.Getenv("PDF_ENABLE_OPERATIONAL_ALARMS")) == "1" {
		applicationMonitoring(stack, logs, paymentLogs, alb, targets, service, payment, table)
	}
	for name, value := range map[string]*string{"PaymentMode": jsii.String(paymentCfg.Mode), "PaymentPayTo": jsii.String(paymentCfg.PayTo), "ApiUrl": resource, "HealthUrl": health, "ClusterName": cluster.ClusterName(), "ServiceName": service.ServiceName(), "PaymentFunctionArn": alias.FunctionArn(), "PaymentTableName": table.TableName(), "ServerLogGroup": logs.LogGroupName(), "PaymentLogGroup": paymentLogs.LogGroupName(), "AllowedClientCidr": jsii.String(cidr)} {
		awscdk.NewCfnOutput(stack, jsii.String(name), &awscdk.CfnOutputProps{Value: value})
	}
	fmt.Fprintln(os.Stderr, "Synthesizing private PDF stack in", region, "payment mode", paymentCfg.Mode)
	app.Synth(nil)
}

// The owner address remains validated for private operation and rollback.
// Public launch uses its separate explicit mainnet-only access setting.
func ownerCIDR(value string) bool {
	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil {
		return false
	}
	ones, bits := network.Mask.Size()
	return ones == 32 && bits == 32
}

func prototypeDesiredCount(value string) float64 {
	switch value {
	case "", "0":
		return 0
	case "1", "2":
		return map[string]float64{"1": 1, "2": 2}[value]
	default:
		panic("PDF_DESIRED_COUNT must be 0, 1, or the autoscaling cap 2")
	}
}

func autoscalingSetting(value, desired string) bool {
	switch value {
	case "", "0":
		if desired == "2" {
			panic("PDF_DESIRED_COUNT=2 requires PDF_ENABLE_AUTOSCALING=1")
		}
		return false
	case "1":
		if desired != "1" && desired != "2" {
			panic("autoscaling requires an active service at desired count 1 or 2")
		}
		return true
	default:
		panic("PDF_ENABLE_AUTOSCALING must be 0 or 1")
	}
}

func autoscalingConfiguredSetting(value string) bool {
	switch value {
	case "", "0":
		return false
	case "1":
		return true
	default:
		panic("PDF_AUTOSCALING_CONFIGURED must be 0 or 1")
	}
}

func serviceDesiredCount(value string, autoscaling bool) *float64 {
	if autoscaling {
		// Leaving DesiredCount unmanaged prevents ordinary stack updates from
		// overwriting the capacity selected by Application Auto Scaling.
		return nil
	}
	return jsii.Number(prototypeDesiredCount(value))
}

func boundedDeploymentPercentages(public bool) (float64, float64) {
	if public {
		// Keep live traffic on healthy tasks until replacements are ready.
		// Only a rolling deployment may temporarily double the desired count;
		// normal autoscaling retains its one-to-two-task bounds.
		return 100, 200
	}
	// Private tests favor their strict task cost cap over deployment uptime.
	return 0, 100
}

func monitoringSetting(value string) string {
	if value == "0" {
		return "0"
	}
	if value == "" || value == "1" {
		return "1"
	}
	panic("PDF_ENABLE_OPERATIONAL_ALARMS must be 0 or 1")
}

func publicAccessSetting(raw, paymentMode string) bool {
	switch raw {
	case "", "0":
		return false
	case "1":
		if paymentMode != "cdp-base" {
			panic("public access requires Base mainnet mode")
		}
		return true
	default:
		panic("PDF_PUBLIC_ACCESS must be 0 or 1")
	}
}
func boolSetting(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func stackTerminationProtection(local bool) *bool { return jsii.Bool(!local) }

const paymentReservedConcurrency = 4
