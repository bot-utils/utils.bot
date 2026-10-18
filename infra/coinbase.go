package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/jsii-runtime-go"
)

func coinbaseParameters(stack awscdk.Stack, function awslambda.Function, enabled bool) {
	if !enabled {
		return
	}
	requireDeploymentAccount(*stack.Account(), false)
	function.AddEnvironment(jsii.String("CDP_AUTH_CHECK"), jsii.String("1"), nil)
	resources := []*string{}
	for _, name := range []string{"coinbaseAPIKey", "coinbaseAPISecret", "receiveAddress"} {
		resources = append(resources, jsii.String("arn:aws:ssm:us-east-1:"+*stack.Account()+":parameter/pdf/"+name))
	}
	function.AddToRolePolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Actions: &[]*string{jsii.String("ssm:GetParameters")}, Resources: &resources}))
	awscdk.NewCfnOutput(stack, jsii.String("CoinbaseParameterRegion"), &awscdk.CfnOutputProps{Value: jsii.String("us-east-1")})
}
