package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

func csvInfraFixture(t *testing.T) csvPrivateConfig {
	t.Helper()
	c := csvPrivateConfig{Account: "111111111111", SyntheticOnly: true, AllowedIP: "203.0.113.10", KeySHA256: strings.Repeat("b", 64), ALBPeers: []string{"10.0.0.0/24"}, Runs: []csvPrivateRun{{ID: strings.Repeat("a", 64), Until: time.Now().Add(time.Hour).Unix(), Request: json.RawMessage(`{"version":1}`)}}}
	raw, _ := json.Marshal(c)
	t.Setenv("PDF_CSV_PRIVATE_ENABLED", "1")
	t.Setenv("PDF_CSV_PRIVATE_CONFIG", string(raw))
	t.Setenv("PDF_DIRECT_API", "1")
	return c
}
func TestPrivateCSVPermissionScopeAndExpiry(t *testing.T) {
	defer jsii.Close()
	c := csvInfraFixture(t)
	for _, namespace := range []bool{false, true} {
		statements := csvPrivateStatements(c.Account, c, namespace)
		if len(statements) != 4 {
			t.Fatal("unexpected permission family")
		}
		for _, statement := range statements {
			raw, _ := json.Marshal(statement.ToStatementJson())
			text := string(raw)
			for _, forbidden := range []string{"ecs:", "ssm:", "iam:", "lambda:", "sqs:", "BUDGET", "OUTBOX", "payments", "s3:ListBucket", "s3:DeleteObject"} {
				if strings.Contains(text, forbidden) {
					t.Fatal("private API overpermission", forbidden)
				}
			}
			if !strings.Contains(text, "DateLessThan") || !strings.Contains(text, time.Unix(c.Runs[0].Until, 0).UTC().Format(time.RFC3339)) {
				t.Fatal("missing expiry")
			}
			if !namespace && !strings.Contains(text, c.Runs[0].ID[:16]) {
				t.Fatal("identity policy missing exact run")
			}
			if strings.Contains(text, "s3:GetObject") && strings.Contains(text, "/inputs/") || strings.Contains(text, "s3:PutObject") && strings.Contains(text, "/results/") {
				t.Fatal("input-read or result-write permission")
			}
			if strings.Contains(text, "dynamodb:PutItem") && !strings.Contains(text, "TransactWriteItems") {
				t.Fatal("unfenced metadata mutation")
			}
		}
	}
}
func TestPrivateCSVRegionalRuleRequiresSourceIPAndNoNewNetwork(t *testing.T) {
	defer jsii.Close()
	c := csvInfraFixture(t)
	t.Setenv("PDF_HOSTED_ZONE_ID", "Z0123456789ABCDEFGHIJK")
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("CsvPrivateTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(c.Account), Region: jsii.String("us-east-2")}})
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc})
	origin := alb.AddListener(jsii.String("Origin"), &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(8443), Protocol: awselasticloadbalancingv2.ApplicationProtocol_HTTP, DefaultAction: awselasticloadbalancingv2.ListenerAction_FixedResponse(jsii.Number(404), nil)})
	targets := awselasticloadbalancingv2.NewApplicationTargetGroup(stack, jsii.String("Targets"), &awselasticloadbalancingv2.ApplicationTargetGroupProps{Vpc: vpc, Port: jsii.Number(8080), TargetType: awselasticloadbalancingv2.TargetType_IP})
	task := awsecs.NewFargateTaskDefinition(stack, jsii.String("Task"), nil)
	container := task.AddContainer(jsii.String("Server"), &awsecs.ContainerDefinitionOptions{Image: awsecs.ContainerImage_FromRegistry(jsii.String("example.invalid/base"), nil)})
	count := func() map[string]int {
		counts := map[string]int{}
		for _, node := range *stack.Node().FindAll(constructs.ConstructOrder_PREORDER) {
			if resource, ok := node.(awscdk.CfnResource); ok && strings.HasPrefix(*resource.CfnResourceType(), "AWS::EC2::") {
				counts[*resource.CfnResourceType()]++
			}
		}
		return counts
	}
	original := count()
	bindPrivateCSV(c.Account, task, container)
	regionalAPI(stack, alb, targets, origin)
	network := count()
	template := assertions.Template_FromStack(stack, nil)
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(network)
	if string(a) != string(b) {
		t.Fatal("CSV added or changed network resource counts")
	}
	template.HasResourceProperties(jsii.String("AWS::ElasticLoadBalancingV2::ListenerRule"), map[string]interface{}{"Priority": 12, "Conditions": assertions.Match_ArrayWith(&[]interface{}{
		map[string]interface{}{"Field": "source-ip", "SourceIpConfig": map[string]interface{}{"Values": []string{c.AllowedIP + "/32"}}},
	})})
	template.HasResourceProperties(jsii.String("AWS::ECS::TaskDefinition"), map[string]interface{}{"ContainerDefinitions": assertions.Match_ArrayWith(&[]interface{}{
		assertions.Match_ObjectLike(&map[string]interface{}{"Environment": assertions.Match_ArrayWith(&[]interface{}{map[string]interface{}{"Name": "CSV_PRIVATE_ENABLED", "Value": "1"}})}),
	})})
}
func TestPrivateCSVDeploymentDefaultsToDisabled(t *testing.T) {
	t.Setenv("PDF_CSV_PRIVATE_ENABLED", "")
	t.Setenv("PDF_CSV_PRIVATE_CONFIG", "")
	if c, _ := csvPrivateSettings(); c != nil {
		t.Fatal("private API enabled by default")
	}
}
