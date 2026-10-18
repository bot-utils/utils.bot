package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/jsii-runtime-go"
)

func TestGuardrailTemplate(t *testing.T) {
	t.Setenv("PDF_ALERT_EMAIL", "ops@example.test")
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		for _, count := range []string{"0", "1", "2"} {
			t.Run(name+"/tasks-"+count, func(t *testing.T) { testGuardrailTemplate(t, enabled, count) })
		}
	}
}

func testGuardrailTemplate(t *testing.T, enabled bool, count string) {
	t.Helper()
	value := "0"
	if enabled {
		value = "1"
	}
	t.Setenv("PDF_ENABLE_ALARM_EMAIL", value)
	t.Setenv("PDF_DESIRED_COUNT", count)
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("GuardrailTest"), nil)
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc})
	targets := awselasticloadbalancingv2.NewApplicationTargetGroup(stack, jsii.String("Targets"), &awselasticloadbalancingv2.ApplicationTargetGroupProps{Vpc: vpc, Port: jsii.Number(8080), TargetType: awselasticloadbalancingv2.TargetType_IP})
	alb.AddListener(jsii.String("Listener"), &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(80), DefaultAction: awselasticloadbalancingv2.ListenerAction_Forward(&[]awselasticloadbalancingv2.IApplicationTargetGroup{targets}, nil)})
	cluster := awsecs.NewCluster(stack, jsii.String("Cluster"), &awsecs.ClusterProps{Vpc: vpc})
	task := awsecs.NewFargateTaskDefinition(stack, jsii.String("Task"), nil)
	task.AddContainer(jsii.String("Server"), &awsecs.ContainerDefinitionOptions{Image: awsecs.ContainerImage_FromRegistry(jsii.String("example.invalid/test"), nil)})
	service := awsecs.NewFargateService(stack, jsii.String("Service"), &awsecs.FargateServiceProps{Cluster: cluster, TaskDefinition: task})
	function := awslambda.NewFunction(stack, jsii.String("Payment"), &awslambda.FunctionProps{Runtime: awslambda.Runtime_NODEJS_22_X(), Handler: jsii.String("index.handler"), Code: awslambda.Code_FromInline(jsii.String("exports.handler=async()=>({pass:false});"))})
	guardrails(stack, alb, targets, service, function)
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::WAFv2::WebACL"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::WAFv2::WebACLAssociation"), jsii.Number(1))
	alarmCount := 5
	if os.Getenv("PDF_ENABLE_OPERATIONAL_ALARMS") == "0" {
		alarmCount = 0
	}
	template.ResourceCountIs(jsii.String("AWS::CloudWatch::Alarm"), jsii.Number(float64(alarmCount)))
	topicCount := 0
	if enabled {
		topicCount = 1
	}
	template.ResourceCountIs(jsii.String("AWS::SNS::Topic"), jsii.Number(topicCount))
	template.ResourceCountIs(jsii.String("AWS::SNS::Subscription"), jsii.Number(topicCount))
	resources := (*template.ToJSON())["Resources"].(map[string]interface{})
	for _, raw := range resources {
		r := raw.(map[string]interface{})
		props, _ := r["Properties"].(map[string]interface{})
		switch r["Type"] {
		case "AWS::WAFv2::WebACL":
			b, _ := json.Marshal(props)
			if strings.Contains(string(b), `"Body"`) || strings.Contains(string(b), `"Captcha"`) || strings.Contains(string(b), `"Challenge"`) {
				t.Fatal("large-upload or agent-hostile rule")
			}
			rules := props["Rules"].([]interface{})
			if len(rules) != 3 {
				t.Fatal("unexpected WAF rules")
			}
			for _, raw := range rules {
				rule := raw.(map[string]interface{})
				if rule["VisibilityConfig"].(map[string]interface{})["SampledRequestsEnabled"] != false {
					t.Fatal("payment header sampling enabled")
				}
				if rule["Name"] == "PerIpPdfRate" || rule["Name"] == "GlobalRequestRate" {
					statement := rule["Statement"].(map[string]interface{})["RateBasedStatement"].(map[string]interface{})
					wantLimit := float64(60)
					wantKey := "IP"
					if rule["Name"] == "GlobalRequestRate" {
						wantLimit, wantKey = 120, "CONSTANT"
					}
					if statement["Limit"] != wantLimit || statement["AggregateKeyType"] != wantKey || statement["EvaluationWindowSec"] != float64(60) {
						t.Fatal("origin POST rate bound changed", rule["Name"], statement)
					}
					b, _ := json.Marshal(statement["ScopeDownStatement"])
					text := string(b)
					if !strings.Contains(text, `"SearchString":"POST"`) || !strings.Contains(text, `"SearchString":"/v1/pdf/text"`) {
						t.Fatal("origin rate does not apply only to parser POSTs", text)
					}
					if strings.Contains(text, "ForwardedIP") || strings.Contains(text, "Header") || strings.Contains(text, "X-Forwarded-For") {
						t.Fatal("spoofable forwarded IP influences origin rate key", text)
					}
				}
			}
		case "AWS::SNS::Subscription":
			if !enabled || props["Protocol"] != "email" || props["Endpoint"] != "ops@example.test" {
				t.Fatal("wrong alarm recipient", props)
			}
		case "AWS::SNS::TopicPolicy":
			raw, _ := json.Marshal(props["PolicyDocument"])
			if !strings.Contains(string(raw), "aws:SourceAccount") || !strings.Contains(string(raw), "aws:SourceArn") || !strings.Contains(string(raw), "alarm:agent-pdf-*") {
				t.Fatal("unscoped alarm publisher")
			}
		case "AWS::CloudWatch::Alarm":
			if props["ActionsEnabled"] != (count != "0") {
				t.Fatal("alarm actions must pause during intentional shutdown and resume with the service")
			}
			actions, configured := props["AlarmActions"]
			if configured != enabled || (enabled && len(actions.([]interface{})) != 1) {
				t.Fatal("alarm delivery does not match authorized configuration")
			}
			if enabled && len(props["OKActions"].([]interface{})) != 1 {
				t.Fatal("recovery notifications missing")
			}
			if props["AlarmName"] == "agent-pdf-no-healthy-targets" && props["TreatMissingData"] != "breaching" {
				t.Fatal("availability misses absent metrics")
			}
		}
	}
}

func TestDisabledMonitoringRetainsTrafficProtectionAndApprovedSubscription(t *testing.T) {
	t.Setenv("PDF_ALERT_EMAIL", "ops@example.test")
	t.Setenv("PDF_ENABLE_OPERATIONAL_ALARMS", "0")
	testGuardrailTemplate(t, true, "0")
}
