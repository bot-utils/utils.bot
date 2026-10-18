package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/jsii-runtime-go"
)

func TestMonitoringHasFixedCostCardinalityAndPausedShutdownAlarms(t *testing.T) {
	t.Setenv("PDF_ALERT_EMAIL", "ops@example.test")
	for _, count := range []string{"0", "1"} {
		t.Run(count, func(t *testing.T) {
			t.Setenv("PDF_DESIRED_COUNT", count)
			t.Setenv("PDF_ENABLE_ALARM_EMAIL", "1")
			t.Setenv("PDF_MONITORING_DISTRIBUTION_ID", "TESTPRIVATE")
			defer jsii.Close()
			app := awscdk.NewApp(nil)
			stack := awscdk.NewStack(app, jsii.String("MonitoringTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
			vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
			alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc})
			targets := awselasticloadbalancingv2.NewApplicationTargetGroup(stack, jsii.String("Targets"), &awselasticloadbalancingv2.ApplicationTargetGroupProps{Vpc: vpc, Port: jsii.Number(8080), TargetType: awselasticloadbalancingv2.TargetType_IP})
			alb.AddListener(jsii.String("Listener"), &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(80), DefaultAction: awselasticloadbalancingv2.ListenerAction_Forward(&[]awselasticloadbalancingv2.IApplicationTargetGroup{targets}, nil)})
			cluster := awsecs.NewCluster(stack, jsii.String("Cluster"), &awsecs.ClusterProps{Vpc: vpc})
			task := awsecs.NewFargateTaskDefinition(stack, jsii.String("Task"), nil)
			task.AddContainer(jsii.String("Server"), &awsecs.ContainerDefinitionOptions{Image: awsecs.ContainerImage_FromRegistry(jsii.String("example.invalid/test"), nil)})
			service := awsecs.NewFargateService(stack, jsii.String("Service"), &awsecs.FargateServiceProps{Cluster: cluster, TaskDefinition: task})
			function := awslambda.NewFunction(stack, jsii.String("Payment"), &awslambda.FunctionProps{Runtime: awslambda.Runtime_NODEJS_22_X(), Handler: jsii.String("index.handler"), Code: awslambda.Code_FromInline(jsii.String("exports.handler=async()=>({pass:false});"))})
			serverLogs := awslogs.NewLogGroup(stack, jsii.String("ServerLogs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/server"), Retention: awslogs.RetentionDays_ONE_WEEK})
			paymentLogs := awslogs.NewLogGroup(stack, jsii.String("PaymentLogs"), &awslogs.LogGroupProps{LogGroupName: jsii.String("/agent-pdf/mock/payment"), Retention: awslogs.RetentionDays_ONE_WEEK})
			applicationMonitoring(stack, serverLogs, paymentLogs, alb, targets, service, function, paymentBindings(stack))
			template := assertions.Template_FromStack(stack, nil)
			template.ResourceCountIs(jsii.String("AWS::Logs::MetricFilter"), jsii.Number(15))
			template.ResourceCountIs(jsii.String("AWS::CloudWatch::Dashboard"), jsii.Number(1))
			template.ResourceCountIs(jsii.String("AWS::CloudWatch::Alarm"), jsii.Number(4))
			template.ResourceCountIs(jsii.String("AWS::SNS::Subscription"), jsii.Number(0))
			template.ResourceCountIs(jsii.String("AWS::Lambda::Function"), jsii.Number(1))
			resources := (*template.ToJSON())["Resources"].(map[string]any)
			names := map[string]bool{}
			for _, raw := range resources {
				r := raw.(map[string]any)
				props, _ := r["Properties"].(map[string]any)
				switch r["Type"] {
				case "AWS::Logs::MetricFilter":
					transforms := props["MetricTransformations"].([]any)
					if len(transforms) != 1 {
						t.Fatal("extra metric")
					}
					m := transforms[0].(map[string]any)
					if m["Dimensions"] != nil || m["MetricNamespace"] != monitoringNamespace || m["DefaultValue"] != float64(0) {
						t.Fatal("metric cardinality or namespace changed")
					}
					name := m["MetricName"].(string)
					if names[name] {
						t.Fatal("duplicate metric")
					}
					names[name] = true
					if !strings.HasPrefix(m["MetricValue"].(string), "$.") || !strings.Contains(props["FilterPattern"].(string), `$.telemetry = "summary"`) {
						t.Fatal("metric not using bounded summaries")
					}
				case "AWS::CloudWatch::Alarm":
					if props["ActionsEnabled"] != (count == "1") || props["TreatMissingData"] != "notBreaching" {
						t.Fatal("stopped alarms active")
					}
					b, _ := json.Marshal(props["AlarmActions"])
					if !strings.Contains(string(b), "agent-pdf-alerts") || props["Period"] != nil && props["Period"].(float64) < 60 {
						t.Fatal("wrong destination or high resolution")
					}
				case "AWS::CloudWatch::Dashboard":
					body, _ := json.Marshal(props["DashboardBody"])
					if props["DashboardName"] != "agent-pdf" || strings.Contains(string(body), `\"type\":\"log\"`) || strings.Contains(string(body), "query") || strings.Contains(string(body), "functionArn") {
						t.Fatal("paid query or compute widget")
					}
				case "AWS::Logs::LogGroup":
					if props["RetentionInDays"] != float64(7) {
						t.Fatal("log retention increased")
					}
				}
			}
		})
	}
}
