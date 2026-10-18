package main

import (
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudwatch"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudwatchactions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awssns"
	"github.com/aws/jsii-runtime-go"
)

const monitoringNamespace = "AgentPdf/Operations"

// Fifteen fixed metrics, no identifier dimensions, and one private metric-only
// dashboard. Log queries, tracing, Container Insights and paid canaries are not
// enabled. Filters reuse the two existing seven-day application log groups.
func applicationMonitoring(stack awscdk.Stack, serverLogs, paymentLogs awslogs.LogGroup, alb awselasticloadbalancingv2.ApplicationLoadBalancer, targets awselasticloadbalancingv2.ApplicationTargetGroup, service awsecs.FargateService, payment awslambda.Function, table awsdynamodb.Table) {
	definitions := []struct{ role, field, name string }{
		{"server", "requests", "Requests"}, {"server", "completed", "Completed"}, {"server", "document_failures", "DocumentFailures"}, {"server", "service_failures", "ServiceFailures"}, {"server", "paid_service_failures", "PaidServiceFailures"}, {"server", "capacity_refusals", "CapacityRefusals"}, {"server", "fallback_attempts", "FallbackAttempts"},
		{"payment", "verify_calls", "VerifyCalls"}, {"payment", "verify_rejected", "VerifyRejected"}, {"payment", "provider_failures", "ProviderFailures"}, {"payment", "settlement_attempts", "SettlementAttempts"}, {"payment", "settlement_confirmed", "SettlementConfirmed"}, {"payment", "binding_failures", "BindingFailures"}, {"payment", "paid_retries", "PaidRetries"}, {"payment", "binding_created", "BindingCreated"},
	}
	custom := map[string]awscloudwatch.IMetric{}
	groups := map[string]awslogs.LogGroup{"server": serverLogs, "payment": paymentLogs}
	for _, d := range definitions {
		awslogs.NewCfnMetricFilter(stack, jsii.String("Metric"+d.name), &awslogs.CfnMetricFilterProps{
			LogGroupName: groups[d.role].LogGroupName(), FilterName: jsii.String("agent-pdf-" + d.name),
			FilterPattern:         jsii.String(`{ $.telemetry = "summary" && $.role = "` + d.role + `" }`),
			MetricTransformations: []any{map[string]any{"metricNamespace": monitoringNamespace, "metricName": d.name, "metricValue": "$." + d.field, "defaultValue": 0, "unit": "Count"}},
		})
		custom[d.name] = awscloudwatch.NewMetric(&awscloudwatch.MetricProps{Namespace: jsii.String(monitoringNamespace), MetricName: jsii.String(d.name), Period: awscdk.Duration_Minutes(jsii.Number(1)), Statistic: jsii.String("Sum")})
	}
	sum := &awscloudwatch.MetricOptions{Period: awscdk.Duration_Minutes(jsii.Number(1)), Statistic: jsii.String("Sum")}
	var topic awssns.ITopic
	if os.Getenv("PDF_ENABLE_ALARM_EMAIL") == "1" {
		topic = awssns.Topic_FromTopicArn(stack, jsii.String("MonitoringAlertTopic"), stack.FormatArn(&awscdk.ArnComponents{Service: jsii.String("sns"), Resource: jsii.String("agent-pdf-alerts")}))
	}
	alarm := func(name string, metric awscloudwatch.IMetric, threshold, periods float64, description string) {
		a := awscloudwatch.NewAlarm(stack, jsii.String("Monitoring"+name), &awscloudwatch.AlarmProps{AlarmName: jsii.String("agent-pdf-" + name), Metric: metric, Threshold: jsii.Number(threshold), EvaluationPeriods: jsii.Number(periods), ComparisonOperator: awscloudwatch.ComparisonOperator_GREATER_THAN_OR_EQUAL_TO_THRESHOLD, TreatMissingData: awscloudwatch.TreatMissingData_NOT_BREACHING, ActionsEnabled: jsii.Bool(prototypeDesiredCount(os.Getenv("PDF_DESIRED_COUNT")) == 1), AlarmDescription: jsii.String(description)})
		if topic != nil {
			a.AddAlarmAction(awscloudwatchactions.NewSnsAction(topic))
			a.AddOkAction(awscloudwatchactions.NewSnsAction(topic))
		}
	}
	alarm("provider-failures", custom["ProviderFailures"], 1, 1, "Coinbase authentication, billing, transport, pending settlement or malformed response; inspect bounded diagnostics")
	alarm("paid-service-failures", custom["PaidServiceFailures"], 1, 1, "Confirmed payment followed by server failure or detected response write failure")
	alarm("payment-errors", payment.MetricErrors(sum), 1, 1, "Payment Lambda runtime error, timeout or initialization failure")
	incoming := func(group awslogs.LogGroup) awscloudwatch.IMetric {
		return awscloudwatch.NewMetric(&awscloudwatch.MetricProps{Namespace: jsii.String("AWS/Logs"), MetricName: jsii.String("IncomingBytes"), DimensionsMap: &map[string]*string{"LogGroupName": group.LogGroupName()}, Period: awscdk.Duration_Hours(jsii.Number(1)), Statistic: jsii.String("Sum")})
	}
	volume := awscloudwatch.NewMathExpression(&awscloudwatch.MathExpressionProps{Expression: jsii.String("server+payment"), UsingMetrics: &map[string]awscloudwatch.IMetric{"server": incoming(serverLogs), "payment": incoming(paymentLogs)}, Period: awscdk.Duration_Hours(jsii.Number(1)), Label: jsii.String("Application log bytes/hour")})
	alarm("log-volume", volume, 10*1024*1024, 2, "Both application log groups ingested >=10 MiB/hour for two hours; warning only, not a hard spending cap")
	dashboard := awscloudwatch.NewDashboard(stack, jsii.String("OperationsDashboard"), &awscloudwatch.DashboardProps{DashboardName: jsii.String("agent-pdf"), PeriodOverride: awscloudwatch.PeriodOverride_INHERIT, DefaultInterval: awscdk.Duration_Hours(jsii.Number(6))})
	panel := func(title string, metrics ...awscloudwatch.IMetric) awscloudwatch.IWidget {
		return awscloudwatch.NewGraphWidget(&awscloudwatch.GraphWidgetProps{Title: jsii.String(title), Width: jsii.Number(12), Height: jsii.Number(6), Left: &metrics, Period: awscdk.Duration_Minutes(jsii.Number(5))})
	}
	dashboard.AddWidgets(awscloudwatch.NewTextWidget(&awscloudwatch.TextWidgetProps{Width: jsii.Number(24), Height: jsii.Number(3), Markdown: jsii.String("# utils.bot operations\nPayments are provider-confirmed, not an independent chain/account-credit audit. Completed means server response write succeeded; it does not prove client receipt. Expected document failures are separate from paid service failures. No request, wallet or document IDs are metric dimensions. Application detail logs expire after seven days; alarms pause when Fargate is intentionally stopped.")}))
	dashboard.AddWidgets(panel("Payment verification and provider health", custom["VerifyCalls"], custom["VerifyRejected"], custom["ProviderFailures"], payment.MetricErrors(sum), payment.MetricThrottles(sum)), panel("Settlements and immutable bindings", custom["SettlementAttempts"], custom["SettlementConfirmed"], custom["BindingCreated"], custom["BindingFailures"], custom["PaidRetries"]))
	dashboard.AddWidgets(panel("PDF outcomes and capacity", custom["Requests"], custom["Completed"], custom["DocumentFailures"], custom["CapacityRefusals"], custom["FallbackAttempts"]), panel("Service failures", custom["ServiceFailures"], custom["PaidServiceFailures"], alb.MetricHttpCodeTarget(awselasticloadbalancingv2.HttpCodeTarget_TARGET_5XX_COUNT, sum)))
	dashboard.AddWidgets(panel("Latency (seconds)", alb.MetricTargetResponseTime(&awscloudwatch.MetricOptions{Statistic: jsii.String("p95")})), panel("Payment Lambda latency (milliseconds)", payment.MetricDuration(&awscloudwatch.MetricOptions{Statistic: jsii.String("p95")})))
	dashboard.AddWidgets(panel("Task CPU and memory (%)", service.MetricCpuUtilization(nil), service.MetricMemoryUtilization(nil)), panel("Healthy targets", targets.MetricHealthyHostCount(&awscloudwatch.MetricOptions{Statistic: jsii.String("Minimum")})))
	dashboard.AddWidgets(panel("Application log ingestion", incoming(serverLogs), incoming(paymentLogs)), panel("DynamoDB throttling", table.MetricThrottledRequestsForOperations(&awsdynamodb.OperationsMetricOptions{Operations: &[]awsdynamodb.Operation{awsdynamodb.Operation_GET_ITEM, awsdynamodb.Operation_PUT_ITEM}, Period: awscdk.Duration_Minutes(jsii.Number(5)), Statistic: jsii.String("Sum")})))
	// CloudFront/WAF supply ordinary service metrics in us-east-1. No paid
	// additional CloudFront metrics or sampled request/body logs are enabled.
	frontend := func(namespace, name string, dims map[string]*string) awscloudwatch.IMetric {
		return awscloudwatch.NewMetric(&awscloudwatch.MetricProps{Namespace: jsii.String(namespace), MetricName: jsii.String(name), Region: jsii.String("us-east-1"), DimensionsMap: &dims, Statistic: jsii.String("Sum")})
	}
	if distribution := os.Getenv("PDF_MONITORING_DISTRIBUTION_ID"); distribution != "" {
		dashboard.AddWidgets(panel("CloudFront requests", frontend("AWS/CloudFront", "Requests", map[string]*string{"DistributionId": jsii.String(distribution), "Region": jsii.String("Global")})), panel("Edge WAF blocked requests", frontend("AWS/WAFV2", "BlockedRequests", map[string]*string{"WebACL": jsii.String("agent-pdf-edge"), "Rule": jsii.String("ALL")})))
	}
	awscdk.NewCfnOutput(stack, jsii.String("MonitoringDashboardName"), &awscdk.CfnOutputProps{Value: dashboard.DashboardName()})
}
