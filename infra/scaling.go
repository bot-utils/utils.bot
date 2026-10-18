package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapplicationautoscaling"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/jsii-runtime-go"
)

func boundedServiceDeployment(public bool) *awsecs.FargateServiceProps {
	minimum, maximum := boundedDeploymentPercentages(public)
	return &awsecs.FargateServiceProps{
		MinHealthyPercent: jsii.Number(minimum), MaxHealthyPercent: jsii.Number(maximum),
		// Rebalance only through explicit deployments or demand-based scaling.
		AvailabilityZoneRebalancing: awsecs.AvailabilityZoneRebalancing_DISABLED,
	}
}

func configureServiceAutoscaling(service awsecs.FargateService, targets awselasticloadbalancingv2.ApplicationTargetGroup) {
	scaling := service.AutoScaleTaskCount(&awsapplicationautoscaling.EnableScalingProps{
		MinCapacity: jsii.Number(1), MaxCapacity: jsii.Number(2),
	})
	scaling.ScaleOnRequestCount(jsii.String("RequestScaling"), &awsecs.RequestCountScalingProps{
		TargetGroup: targets, RequestsPerTarget: jsii.Number(6),
		ScaleOutCooldown: awscdk.Duration_Seconds(jsii.Number(60)),
		ScaleInCooldown:  awscdk.Duration_Seconds(jsii.Number(300)),
	})
}
