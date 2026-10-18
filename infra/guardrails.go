package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudwatch"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudwatchactions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awssns"
	"github.com/aws/aws-cdk-go/awscdk/v2/awssnssubscriptions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awswafv2"
	"github.com/aws/jsii-runtime-go"
	"os"
)

// Protect the generated ALB hostname without changing owner-IP ingress.
func guardrails(stack awscdk.Stack, alb awselasticloadbalancingv2.ApplicationLoadBalancer, targets awselasticloadbalancingv2.ApplicationTargetGroup, service awsecs.FargateService, payment awslambda.Function) {
	visibility := func(name string) map[string]any {
		return map[string]any{"cloudWatchMetricsEnabled": true, "sampledRequestsEnabled": false, "metricName": name}
	}
	match := func(field, value string) map[string]any {
		return map[string]any{"byteMatchStatement": map[string]any{"fieldToMatch": map[string]any{field: map[string]any{}}, "positionalConstraint": "EXACTLY", "searchString": value, "textTransformations": []any{map[string]any{"priority": 0, "type": "NONE"}}}}
	}
	api := map[string]any{"andStatement": map[string]any{"statements": []any{match("method", "POST"), match("uriPath", "/v1/pdf/text")}}}
	rateAction := map[string]any{"block": map[string]any{"customResponse": map[string]any{"responseCode": 429, "customResponseBodyKey": "rateLimited", "responseHeaders": []any{map[string]any{"name": "Retry-After", "value": "60"}}}}}
	allowed := map[string]any{"orStatement": map[string]any{"statements": []any{match("method", "GET"), match("method", "HEAD"), api}}}
	rules := []any{
		map[string]any{"name": "AllowedMethods", "priority": 0, "statement": map[string]any{"notStatement": map[string]any{"statement": allowed}}, "action": map[string]any{"block": map[string]any{"customResponse": map[string]any{"responseCode": 403, "customResponseBodyKey": "routeDenied"}}}, "visibilityConfig": visibility("agent-pdf-methods")},
		map[string]any{"name": "PerIpPdfRate", "priority": 1, "statement": map[string]any{"rateBasedStatement": map[string]any{"limit": 60, "evaluationWindowSec": 60, "aggregateKeyType": "IP", "scopeDownStatement": api}}, "action": rateAction, "visibilityConfig": visibility("agent-pdf-ip-rate")},
		map[string]any{"name": "GlobalRequestRate", "priority": 2, "statement": map[string]any{"rateBasedStatement": map[string]any{"limit": 120, "evaluationWindowSec": 60, "aggregateKeyType": "CONSTANT", "scopeDownStatement": api}}, "action": rateAction, "visibilityConfig": visibility("agent-pdf-global-rate")},
	}
	acl := awswafv2.NewCfnWebACL(stack, jsii.String("TrafficProtection"), &awswafv2.CfnWebACLProps{Name: jsii.String("agent-pdf-mock"), Scope: jsii.String("REGIONAL"), DefaultAction: map[string]any{"allow": map[string]any{}}, VisibilityConfig: visibility("agent-pdf-web-acl"), Rules: rules, CustomResponseBodies: map[string]any{
		"rateLimited": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"rate_limited"}`},
		"routeDenied": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"method_or_route_not_allowed"}`},
	}})
	awswafv2.NewCfnWebACLAssociation(stack, jsii.String("TrafficProtectionAssociation"), &awswafv2.CfnWebACLAssociationProps{ResourceArn: alb.LoadBalancerArn(), WebAclArn: acl.AttrArn()})
	awscdk.NewCfnOutput(stack, jsii.String("WebAclArn"), &awscdk.CfnOutputProps{Value: acl.AttrArn()})
	operationalAlarms(stack, alb, targets, service, payment)
}

func operationalAlarms(stack awscdk.Stack, alb awselasticloadbalancingv2.ApplicationLoadBalancer, targets awselasticloadbalancingv2.ApplicationTargetGroup, service awsecs.FargateService, payment awslambda.Function) {
	var topic awssns.Topic
	if os.Getenv("PDF_ENABLE_ALARM_EMAIL") == "1" {
		topic = awssns.NewTopic(stack, jsii.String("OperationalAlerts"), &awssns.TopicProps{TopicName: jsii.String("agent-pdf-alerts")})
		topic.AddSubscription(awssnssubscriptions.NewEmailSubscription(jsii.String(alertEmail()), nil))
		topic.AddToResourcePolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
			Actions: &[]*string{jsii.String("sns:Publish")}, Resources: &[]*string{topic.TopicArn()},
			Principals: &[]awsiam.IPrincipal{awsiam.NewServicePrincipal(jsii.String("cloudwatch.amazonaws.com"), nil)},
			Conditions: &map[string]interface{}{"StringEquals": map[string]any{"aws:SourceAccount": stack.Account()}, "ArnLike": map[string]any{"aws:SourceArn": "arn:aws:cloudwatch:" + *stack.Region() + ":" + *stack.Account() + ":alarm:agent-pdf-*"}},
		}))
		awscdk.NewCfnOutput(stack, jsii.String("OperationalAlertTopicArn"), &awscdk.CfnOutputProps{Value: topic.TopicArn()})
	}
	if os.Getenv("PDF_ENABLE_OPERATIONAL_ALARMS") == "0" {
		return
	}
	metricOptions := &awscloudwatch.MetricOptions{Period: awscdk.Duration_Minutes(jsii.Number(1)), Statistic: jsii.String("Sum")}
	alarm := func(name string, metric awscloudwatch.IMetric, threshold, periods float64, operator awscloudwatch.ComparisonOperator) {
		missing := awscloudwatch.TreatMissingData_NOT_BREACHING
		if name == "no-healthy-targets" {
			missing = awscloudwatch.TreatMissingData_BREACHING
		}
		// A deliberate zero-task shutdown is not an outage. Resume alarm actions
		// with the same explicit deployment that starts the service.
		a := awscloudwatch.NewAlarm(stack, jsii.String(name), &awscloudwatch.AlarmProps{AlarmName: jsii.String("agent-pdf-" + name), Metric: metric, Threshold: jsii.Number(threshold), EvaluationPeriods: jsii.Number(periods), ComparisonOperator: operator, TreatMissingData: missing, ActionsEnabled: jsii.Bool(prototypeDesiredCount(os.Getenv("PDF_DESIRED_COUNT")) > 0), AlarmDescription: jsii.String("PDF service operational safeguard")})
		if topic != nil {
			a.AddAlarmAction(awscloudwatchactions.NewSnsAction(topic))
			a.AddOkAction(awscloudwatchactions.NewSnsAction(topic))
		}
	}
	alarm("target-5xx", alb.MetricHttpCodeTarget(awselasticloadbalancingv2.HttpCodeTarget_TARGET_5XX_COUNT, metricOptions), 5, 1, awscloudwatch.ComparisonOperator_GREATER_THAN_OR_EQUAL_TO_THRESHOLD)
	alarm("no-healthy-targets", targets.MetricHealthyHostCount(&awscloudwatch.MetricOptions{Period: awscdk.Duration_Minutes(jsii.Number(1)), Statistic: jsii.String("Minimum")}), 1, 2, awscloudwatch.ComparisonOperator_LESS_THAN_THRESHOLD)
	alarm("payment-throttles", payment.MetricThrottles(metricOptions), 1, 1, awscloudwatch.ComparisonOperator_GREATER_THAN_OR_EQUAL_TO_THRESHOLD)
	alarm("high-cpu", service.MetricCpuUtilization(&awscloudwatch.MetricOptions{Period: awscdk.Duration_Minutes(jsii.Number(1)), Statistic: jsii.String("Average")}), 85, 5, awscloudwatch.ComparisonOperator_GREATER_THAN_THRESHOLD)
	alarm("high-memory", service.MetricMemoryUtilization(&awscloudwatch.MetricOptions{Period: awscdk.Duration_Minutes(jsii.Number(1)), Statistic: jsii.String("Maximum")}), 75, 2, awscloudwatch.ComparisonOperator_GREATER_THAN_THRESHOLD)
}
