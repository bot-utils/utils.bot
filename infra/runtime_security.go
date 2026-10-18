package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

// ECS cannot yet restrict this trust condition to a single cluster. Restrict
// both roles to ECS requests from this account and deployment region instead.
func hardenTaskRoles(task awsecs.FargateTaskDefinition) {
	// Retention keeps replaced definitions active for manual rollback; no
	// additional running task or compute charge is created by this metadata.
	task.ApplyRemovalPolicy(awscdk.RemovalPolicy_RETAIN)
	stack := awscdk.Stack_Of(task)
	source := awscdk.Fn_Join(jsii.String(""), &[]*string{jsii.String("arn:"), stack.Partition(), jsii.String(":ecs:"), stack.Region(), jsii.String(":"), stack.Account(), jsii.String(":*")})
	for _, role := range []awsiam.IRole{task.TaskRole(), task.ExecutionRole()} {
		resource := role.Node().DefaultChild().(awsiam.CfnRole)
		resource.AddPropertyOverride(jsii.String("AssumeRolePolicyDocument"), map[string]any{
			"Version": "2012-10-17", "Statement": []any{map[string]any{
				"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]any{"Service": "ecs-tasks.amazonaws.com"},
				"Condition": map[string]any{"StringEquals": map[string]any{"aws:SourceAccount": stack.Account()}, "ArnLike": map[string]any{"aws:SourceArn": source}},
			}},
		})
	}
}
