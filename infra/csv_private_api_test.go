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

func TestPrivateUploadIdentityAndBoundaryRemainBounded(t *testing.T) {
	defer jsii.Close()
	c := csvInfraFixture(t)
	raw, _ := json.Marshal(map[string]interface{}{"Version": "2012-10-17", "Statement": func() []interface{} {
		var out []interface{}
		for _, s := range csvBoundaryStatements(c.Account, c) {
			out = append(out, s.ToStatementJson())
		}
		return out
	}()})
	// The observed live base is 2,106 compact bytes. Leave room for its statements
	// while staying below IAM's 6,144 non-whitespace character limit.
	if len(raw)+2106 > 6144 {
		t.Fatalf("runtime boundary would exceed IAM limit: %d", len(raw)+2106)
	}
	for _, s := range csvUploadStatements(c.Account, c.Runs[0], false) {
		raw, _ := json.Marshal(s.ToStatementJson())
		text := string(raw)
		for _, bad := range []string{"ecs:", "iam:", "sts:", "ssm:", "lambda:", "sqs:ReceiveMessage", "sqs:DeleteMessage", "s3:CreateBucket"} {
			if strings.Contains(text, bad) {
				t.Fatal("upload coordinator overpermission", bad)
			}
		}
		if !strings.Contains(text, c.Runs[0].ID[:16]) || !strings.Contains(text, "DateLessThan") {
			t.Fatal("unpinned coordinator permissions")
		}
		if strings.Contains(text, "s3:PutObject") && strings.Contains(text, "/results/") {
			t.Fatal("coordinator can write result")
		}
	}
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("CsvCoordinatorTrust"), nil)
	bindCSVUploadCoordinators(c.Account, c, stack)
	template := assertions.Template_FromStack(stack, nil)
	template.HasResourceProperties(jsii.String("AWS::IAM::Role"), map[string]interface{}{
		"RoleName":                 "AgentPdfMock-CsvUpload-" + c.Runs[0].ID[:16],
		"PermissionsBoundary":      namedPolicyArn(c.Account, runtimeBoundaryName),
		"AssumeRolePolicyDocument": map[string]interface{}{"Version": "2012-10-17", "Statement": []interface{}{map[string]interface{}{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": map[string]interface{}{"AWS": "arn:aws:iam::" + c.Account + ":role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_LocalCLIAccess_452e4a519811dc0f"}, "Condition": map[string]interface{}{"StringEquals": map[string]interface{}{"sts:RoleSessionName": "csv-upload-" + c.Runs[0].ID[:16]}, "DateLessThan": map[string]interface{}{"aws:CurrentTime": time.Unix(c.Runs[0].Until, 0).UTC().Format(time.RFC3339)}}}}},
	})
}

func TestPrivateRetirementKeyIsCoordinatorOnly(t *testing.T) {
	defer jsii.Close()
	c := csvInfraFixture(t)
	for _, namespace := range []bool{false, true} {
		statements := csvUploadStatements(c.Account, c.Runs[0], namespace)
		want := "API_RETIRE/" + c.Runs[0].ID
		if namespace {
			want = "API_RETIRE/*"
		}
		reads, writes := 0, 0
		for _, s := range statements {
			raw, _ := json.Marshal(s.ToStatementJson())
			text := string(raw)
			if strings.Contains(text, "dynamodb:") {
				if !strings.Contains(text, want) || strings.Contains(text, "SETTLEMENT") || strings.Contains(text, "PAYMENT") || strings.Contains(text, "DOWNLOAD/") {
					t.Fatal("wrong retirement scope")
				}
				if strings.Contains(text, "dynamodb:GetItem") {
					reads++
				}
				if strings.Contains(text, "dynamodb:PutItem") {
					writes++
				}
			}
		}
		if reads != 1 || writes != 1 {
			t.Fatal("retirement read/write missing")
		}
	}
	for _, s := range csvPrivateStatements(c.Account, c, false) {
		raw, _ := json.Marshal(s.ToStatementJson())
		if strings.Contains(string(raw), "API_RETIRE") {
			t.Fatal("API received retirement permission")
		}
	}
}

func TestPrivateCSVPolicyExportUsesOrdinaryIAMConditionMaps(t *testing.T) {
	defer jsii.Close()
	c := csvInfraFixture(t)
	app := awscdk.NewApp(&awscdk.AppProps{AutoSynth: jsii.Bool(false)})
	stack := awscdk.NewStack(app, jsii.String("CsvPolicyExport"), nil)
	var statements []interface{}
	for _, s := range csvPrivateStatements(c.Account, c, false) {
		statements = append(statements, s.ToStatementJson())
	}
	raw, err := marshalPrivateCSVPolicies(stack, map[string]interface{}{"Version": "2012-10-17", "Statement": statements})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "$jsii") || strings.Contains(string(raw), "${Token[") {
		t.Fatalf("unresolved export: %s", raw)
	}
	var doc struct {
		Statement []struct{ Condition map[string]json.RawMessage }
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var expiry map[string]string
	if err := json.Unmarshal(doc.Statement[0].Condition["DateLessThan"], &expiry); err != nil {
		t.Fatal(err)
	}
	if expiry["aws:CurrentTime"] != time.Unix(c.Runs[0].Until, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("invalid expiry: %s", raw)
	}
	var keys map[string][]string
	if err := json.Unmarshal(doc.Statement[2].Condition["ForAllValues:StringLike"], &keys); err != nil || len(keys["dynamodb:LeadingKeys"]) == 0 {
		t.Fatalf("invalid keys: %s", raw)
	}
}

func TestPrivateCSVPolicyExportRejectsMalformedWrappers(t *testing.T) {
	for _, value := range []interface{}{
		map[string]interface{}{"$jsii.map": map[string]interface{}{}, "Effect": "Allow"},
		map[string]interface{}{"$jsii.map": "bad"},
		map[string]interface{}{"$jsii.byref": "bad"},
		"${Token[TOKEN.123]}",
	} {
		if _, err := normalizePrivateCSVJSON(value); err == nil {
			t.Fatalf("accepted unresolved value: %#v", value)
		}
	}
}
