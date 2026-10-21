package main

import (
	"os"
	"strings"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsevents"
	"github.com/aws/aws-cdk-go/awscdk/v2/awseventstargets"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/jsii-runtime-go"
)

// A deliberate, disposable integration stack. It adds only an owner-source-IP
// rule to the existing listener; PDF resources and real settlement are untouched.
func htmlIntegrationStack(app awscdk.App, account, region string) awscdk.Stack {
	listener := os.Getenv("PDF_HTML_TEST_LISTENER_ARN")
	if !dedicatedExecutionSetting(os.Getenv("PDF_USE_DEDICATED_EXECUTION_ROLE")) || !htmlEnabled() || !htmlJavaScript() || !ownerCIDR(os.Getenv("PDF_ALLOWED_CIDR")) || !strings.HasPrefix(listener, "arn:aws:elasticloadbalancing:"+region+":"+account+":listener/app/agent-pdf-mock/") {
		panic("HTML integration requires bounded IAM, JavaScript, owner /32 and the reviewed existing API listener")
	}
	stack := awscdk.NewStack(app, jsii.String("AgentPdfMock-HtmlTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)}, Synthesizer: pdfStackSynthesizer(account)})
	awscdk.Tags_Of(stack).Add(jsii.String("Project"), jsii.String("agent-pdf"), nil)
	applyRuntimeBoundary(stack, account, false)
	table := awsdynamodb.NewTable(stack, jsii.String("TestBindings"), &awsdynamodb.TableProps{TableName: jsii.String("agent-pdf-html-test-payments"), PartitionKey: &awsdynamodb.Attribute{Name: jsii.String("paymentKey"), Type: awsdynamodb.AttributeType_STRING}, BillingMode: awsdynamodb.BillingMode_PAY_PER_REQUEST, MaxReadRequestUnits: jsii.Number(25), MaxWriteRequestUnits: jsii.Number(25), TimeToLiveAttribute: jsii.String("expiresAt"), RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
	logs := awslogs.NewLogGroup(stack, jsii.String("TestPaymentLogs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/html-test-payment"), Retention: awslogs.RetentionDays_ONE_WEEK, RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
	cfg := paymentConfig{Mode: "mock", PayTo: "0x1111111111111111111111111111111111111111"}
	resource := "https://" + regionalAPIHost + htmlAPIPath
	payment := awslambda.NewFunction(stack, jsii.String("TestPayment"), &awslambda.FunctionProps{FunctionName: jsii.String("agent-pdf-html-test-payment"), Runtime: awslambda.Runtime_PROVIDED_AL2023(), Architecture: awslambda.Architecture_ARM_64(), Handler: jsii.String("bootstrap"), Code: awslambda.Code_FromAsset(jsii.String("../build/payment"), nil), MemorySize: jsii.Number(256), Timeout: awscdk.Duration_Seconds(jsii.Number(20)), ReservedConcurrentExecutions: jsii.Number(2), LogGroup: logs, Environment: &map[string]*string{"PAYMENT_MODE": jsii.String("mock"), "PAYMENT_PAY_TO": jsii.String(cfg.PayTo), "PAYMENT_TABLE": table.TableName(), "RESOURCE_URL": jsii.String(resource), "HTML_RESOURCE_URL": jsii.String(resource)}})
	payment.AddToRolePolicy(allow(jsii.Strings("dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"), jsii.Strings(*table.TableArn())))
	alias := awslambda.NewAlias(stack, jsii.String("TestPaymentAlias"), &awslambda.AliasProps{AliasName: jsii.String("live"), Version: payment.CurrentVersion()})
	controller := htmlFunctions(stack, alias, cfg)
	permission := awslambda.NewCfnPermission(stack, jsii.String("TestAlbPermission"), &awslambda.CfnPermissionProps{Action: jsii.String("lambda:InvokeFunction"), FunctionName: controller.FunctionArn(), Principal: jsii.String("elasticloadbalancing.amazonaws.com"), SourceAccount: jsii.String(account), SourceArn: jsii.String("arn:aws:elasticloadbalancing:" + region + ":" + account + ":targetgroup/agent-pdf-mock-html-test/*")})
	target := awselasticloadbalancingv2.NewCfnTargetGroup(stack, jsii.String("TestTargets"), &awselasticloadbalancingv2.CfnTargetGroupProps{Name: jsii.String("agent-pdf-mock-html-test"), TargetType: jsii.String("lambda"), HealthCheckEnabled: jsii.Bool(false), TargetGroupAttributes: []any{map[string]any{"key": "lambda.multi_value_headers.enabled", "value": "true"}}, Targets: []any{map[string]any{"id": controller.FunctionArn()}}})
	target.AddDependency(permission)
	awselasticloadbalancingv2.NewCfnListenerRule(stack, jsii.String("TestRoute"), &awselasticloadbalancingv2.CfnListenerRuleProps{ListenerArn: jsii.String(listener), Priority: jsii.Number(11), Conditions: []any{map[string]any{"field": "host-header", "hostHeaderConfig": map[string]any{"values": []string{regionalAPIHost}}}, map[string]any{"field": "path-pattern", "pathPatternConfig": map[string]any{"values": []string{htmlAPIPath}}}, map[string]any{"field": "source-ip", "sourceIpConfig": map[string]any{"values": []string{os.Getenv("PDF_ALLOWED_CIDR")}}}, map[string]any{"field": "http-request-method", "httpRequestMethodConfig": map[string]any{"values": []string{"POST", "OPTIONS"}}}}, Actions: []any{map[string]any{"type": "forward", "targetGroupArn": target.Ref()}}})
	networkLogs := awslogs.NewLogGroup(stack, jsii.String("TestNetworkLogs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/html-network-check"), Retention: awslogs.RetentionDays_ONE_WEEK, RemovalPolicy: awscdk.RemovalPolicy_DESTROY})
	network := awslambda.NewFunction(stack, jsii.String("TestNetworkCheck"), &awslambda.FunctionProps{FunctionName: jsii.String("agent-pdf-html-network-check"), Runtime: awslambda.Runtime_PROVIDED_AL2023(), Architecture: awslambda.Architecture_ARM_64(), Handler: jsii.String("bootstrap"), Code: awslambda.Code_FromAsset(jsii.String("../build/html-network-check"), nil), MemorySize: jsii.Number(128), Timeout: awscdk.Duration_Seconds(jsii.Number(8)), ReservedConcurrentExecutions: jsii.Number(1), LogGroup: networkLogs})
	stack.Node().FindChild(jsii.String("HtmlThreatRefresh")).(awsevents.Rule).AddTarget(awseventstargets.NewLambdaFunction(network, &awseventstargets.LambdaFunctionProps{RetryAttempts: jsii.Number(0)}))
	awscdk.NewCfnOutput(stack, jsii.String("TestNetworkCheckName"), &awscdk.CfnOutputProps{Value: network.FunctionName()})
	awscdk.NewCfnOutput(stack, jsii.String("TestPaymentName"), &awscdk.CfnOutputProps{Value: payment.FunctionName()})
	awscdk.NewCfnOutput(stack, jsii.String("TestTableName"), &awscdk.CfnOutputProps{Value: table.TableName()})
	return stack
}
