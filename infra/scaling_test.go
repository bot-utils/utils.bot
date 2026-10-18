package main

import (
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/jsii-runtime-go"
)

func TestRequestAutoscalingIsExplicitlyBoundedAndDoesNotOwnDesiredCount(t *testing.T) {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("ScalingTest"), nil)
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
	cluster := awsecs.NewCluster(stack, jsii.String("Cluster"), &awsecs.ClusterProps{Vpc: vpc})
	task := awsecs.NewFargateTaskDefinition(stack, jsii.String("Task"), nil)
	task.AddContainer(jsii.String("Container"), &awsecs.ContainerDefinitionOptions{Image: awsecs.ContainerImage_FromRegistry(jsii.String("example.invalid/fixture"), nil), PortMappings: &[]*awsecs.PortMapping{{ContainerPort: jsii.Number(8080)}}})
	serviceProps := boundedServiceDeployment(true)
	serviceProps.Cluster, serviceProps.TaskDefinition = cluster, task
	service := awsecs.NewFargateService(stack, jsii.String("Service"), serviceProps)
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc})
	listener := alb.AddListener(jsii.String("Listener"), &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(80)})
	targets := listener.AddTargets(jsii.String("Targets"), &awselasticloadbalancingv2.AddApplicationTargetsProps{Port: jsii.Number(8080), Targets: &[]awselasticloadbalancingv2.IApplicationLoadBalancerTarget{service}})
	configureServiceAutoscaling(service, targets)
	template := assertions.Template_FromStack(stack, nil)
	template.HasResourceProperties(jsii.String("AWS::ECS::Service"), map[string]any{
		"AvailabilityZoneRebalancing": "DISABLED",
		"DeploymentConfiguration":     map[string]any{"MinimumHealthyPercent": 100, "MaximumPercent": 200},
	})
	template.HasResourceProperties(jsii.String("AWS::ApplicationAutoScaling::ScalableTarget"), map[string]any{
		"MinCapacity": 1, "MaxCapacity": 2,
		"ScalableDimension": "ecs:service:DesiredCount", "ServiceNamespace": "ecs",
	})
	template.HasResourceProperties(jsii.String("AWS::ApplicationAutoScaling::ScalingPolicy"), map[string]any{
		"PolicyType": "TargetTrackingScaling",
		"TargetTrackingScalingPolicyConfiguration": map[string]any{
			"TargetValue":                   6,
			"ScaleOutCooldown":              60,
			"ScaleInCooldown":               300,
			"PredefinedMetricSpecification": map[string]any{"PredefinedMetricType": "ALBRequestCountPerTarget"},
		},
	})
	resources := (*template.ToJSON())["Resources"].(map[string]interface{})
	for _, raw := range resources {
		resource := raw.(map[string]interface{})
		if resource["Type"] == "AWS::ECS::Service" {
			properties := resource["Properties"].(map[string]interface{})
			if _, found := properties["DesiredCount"]; found {
				t.Fatal("stack updates would overwrite autoscaler-selected desired count")
			}
		}
	}
}
