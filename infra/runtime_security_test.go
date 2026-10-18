package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/jsii-runtime-go"
)

func TestBothECSRolesHaveOnlyScopedServiceTrust(t *testing.T) {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("TrustTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
	task := awsecs.NewFargateTaskDefinition(stack, jsii.String("Task"), nil)
	task.AddContainer(jsii.String("Server"), &awsecs.ContainerDefinitionOptions{Image: awsecs.ContainerImage_FromRegistry(jsii.String("example.invalid/fixture"), nil)})
	// Registry-only images do not need an execution role until requested.
	task.ObtainExecutionRole()
	hardenTaskRoles(task)
	template := assertions.Template_FromStack(stack, nil)
	template.HasResource(jsii.String("AWS::ECS::TaskDefinition"), map[string]any{"DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain"})
	resources := (*template.ToJSON())["Resources"].(map[string]interface{})
	roles := 0
	for _, raw := range resources {
		r := raw.(map[string]interface{})
		if r["Type"] != "AWS::IAM::Role" {
			continue
		}
		roles++
		p := r["Properties"].(map[string]interface{})["AssumeRolePolicyDocument"].(map[string]interface{})
		statements := p["Statement"].([]interface{})
		if len(statements) != 1 {
			t.Fatal("unconditional trust statement remains")
		}
		statement := statements[0].(map[string]interface{})
		condition := statement["Condition"].(map[string]interface{})
		if condition["StringEquals"].(map[string]interface{})["aws:SourceAccount"] != "111111111111" {
			t.Fatal("cross-account ECS trust")
		}
		data, _ := json.Marshal(condition["ArnLike"])
		if !strings.Contains(string(data), ":ecs:us-east-2:111111111111:*") {
			t.Fatal("unscoped ECS source ARN", string(data))
		}
	}
	if roles != 2 {
		t.Fatal("both task and execution roles must be covered", roles)
	}
}
