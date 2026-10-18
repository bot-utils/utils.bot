package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

func TestDedicatedExecutionFoundationCannotAdministerItself(t *testing.T) {
	t.Setenv("PDF_BOUNDARY_API_CERTIFICATE_ARN", "arn:aws:acm:us-east-2:111111111111:certificate/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	t.Setenv("PDF_BOUNDARY_STATIC_OAC_ID", "EEXAMPLEOAC")
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLEDNS")
	t.Setenv("PDF_BOUNDARY_CLOUDFRONT_DISTRIBUTION_ID", "EDFDVBD6EXAMPLE")
	t.Setenv("PDF_BOUNDARY_ORIGIN_REQUEST_POLICY_ID", "11111111-2222-3333-4444-555555555555")
	t.Setenv("PDF_BOUNDARY_VIEWER_CERTIFICATE_ARN", "arn:aws:acm:us-east-1:111111111111:certificate/11111111-2222-3333-4444-555555555555")
	t.Setenv("PDF_BOUNDARY_ORIGIN_CERTIFICATE_ARN", "arn:aws:acm:us-east-2:111111111111:certificate/66666666-7777-8888-9999-000000000000")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := foundationStack(app, "111111111111", "us-east-2")
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::IAM::Role"), jsii.Number(1))
	template.HasResourceProperties(jsii.String("AWS::IAM::Role"), map[string]any{
		"RoleName":            executionRoleName,
		"PermissionsBoundary": map[string]any{"Ref": assertions.Match_AnyValue()},
		"AssumeRolePolicyDocument": map[string]any{"Statement": []any{map[string]any{
			"Action": "sts:AssumeRole", "Effect": "Allow",
			"Principal": map[string]any{"Service": "cloudformation.amazonaws.com"},
		}}},
	})
	template.HasResourceProperties(jsii.String("AWS::IAM::Policy"), map[string]any{
		"PolicyName": "agent-pdf-pass-dedicated-execution",
		"PolicyDocument": map[string]any{"Statement": []any{map[string]any{
			"Action": "iam:PassRole", "Effect": "Allow",
			"Condition": map[string]any{"StringEquals": map[string]any{"iam:PassedToService": "cloudformation.amazonaws.com"}},
		}}},
	})
	resources := (*template.ToJSON())["Resources"].(map[string]interface{})
	foundExecutionBoundary := false
	foundRuntimeBoundary := false
	foundBootstrapRead := false
	foundScalingTags := false
	foundScalingServiceRole := false
	for _, raw := range resources {
		resource := raw.(map[string]interface{})
		if resource["Type"] == "AWS::IAM::Policy" {
			properties := resource["Properties"].(map[string]interface{})
			encoded, _ := json.Marshal(properties["PolicyDocument"])
			if strings.Contains(string(encoded), "ssm:GetParameters") {
				if !strings.Contains(string(encoded), "parameter/cdk-bootstrap/hnb659fds/version") || strings.Contains(string(encoded), "parameter/pdf/") {
					t.Fatal("execution role bootstrap read can access payment secrets")
				}
				foundBootstrapRead = true
			}
		}
		if resource["Type"] != "AWS::IAM::ManagedPolicy" {
			continue
		}
		properties := resource["Properties"].(map[string]interface{})
		name, _ := properties["ManagedPolicyName"].(string)
		document := properties["PolicyDocument"].(map[string]interface{})
		encoded, _ := json.Marshal(document)
		text := string(encoded)
		switch name {
		case "PDF_AUTOSCALING_DEPLOY":
			for _, raw := range document["Statement"].([]any) {
				statement := raw.(map[string]any)
				if statement["Action"] == "iam:CreateServiceLinkedRole" {
					if statement["Resource"] != "arn:aws:iam::111111111111:role/aws-service-role/ecs.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_ECSService" || statement["Condition"].(map[string]any)["StringEquals"].(map[string]any)["iam:AWSServiceName"] != "ecs.application-autoscaling.amazonaws.com" {
						t.Fatal("autoscaling service-role creation exceeds the exact ECS linked role")
					}
					foundScalingServiceRole = true
				}
				if statement["Action"] != "application-autoscaling:TagResource" {
					continue
				}
				if statement["Resource"] != "arn:aws:application-autoscaling:us-east-2:111111111111:scalable-target/*" || statement["Condition"].(map[string]any)["StringEquals"].(map[string]any)["aws:RequestTag/Project"] != "agent-pdf" {
					t.Fatal("autoscaling tag creation is not confined to this account/region and project")
				}
				foundScalingTags = true
			}
		case executionBoundaryName:
			foundExecutionBoundary = true
			if !strings.Contains(text, "parameter/cdk-bootstrap/hnb659fds/version") || !strings.Contains(text, "ssm:GetParameters") || strings.Contains(text, "parameter/pdf/") {
				t.Fatal("execution ceiling omits bootstrap metadata or includes payment secrets")
			}
			if !strings.Contains(text, "cloudfront:CreateOriginAccessControl") || !strings.Contains(text, ":origin-access-control/EEXAMPLEOAC") || strings.Contains(text, ":origin-access-control/*") {
				t.Fatal("website OAC creation is missing or its established ID is not pinned")
			}
			if len(encoded) > 6144 {
				t.Fatal("execution boundary exceeds the IAM managed-policy size limit", len(encoded))
			}
			for _, forbidden := range []string{"iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion", "iam:DeleteRolePermissionsBoundary", executionRoleName} {
				if strings.Contains(text, forbidden) {
					t.Fatal("execution role can administer its own authority", forbidden)
				}
			}
			for _, broad := range []string{"ec2:*", "ecr:*", "s3:*", "ssm:*", "cloudtrail:*", `"Action":"*"`} {
				if strings.Contains(text, broad) {
					t.Fatal("execution boundary grants broad unrelated service authority", broad)
				}
			}
			if !strings.Contains(text, "AgentPdfMock-*") || !strings.Contains(text, "iam:PermissionsBoundary") {
				t.Fatal("runtime IAM operations are not restricted to bounded PDF roles")
			}
			for _, exact := range []string{"distribution/EDFDVBD6EXAMPLE", "origin-request-policy/11111111-2222-3333-4444-555555555555", "arn:aws:acm:us-east-1:111111111111:certificate/11111111-2222-3333-4444-555555555555", "arn:aws:acm:us-east-2:111111111111:certificate/66666666-7777-8888-9999-000000000000"} {
				if !strings.Contains(text, exact) {
					t.Fatal("existing edge resource is not exactly pinned", exact)
				}
			}
		case runtimeBoundaryName:
			foundRuntimeBoundary = true
			for _, required := range []string{"agent-pdf-mock-payments", "agent-pdf-mock-payment:live", "/pdf/coinbaseAPIKey", "cdk-hnb659fds-container-assets"} {
				if !strings.Contains(text, required) {
					t.Fatal("runtime ceiling omits required exact resource", required)
				}
			}
			if strings.Contains(text, `"Action":"*"`) || strings.Contains(text, `"Action":["*"]`) {
				t.Fatal("runtime ceiling permits arbitrary actions")
			}
		}
	}
	if !foundExecutionBoundary || !foundRuntimeBoundary || !foundBootstrapRead || !foundScalingTags || !foundScalingServiceRole {
		t.Fatal("both permissions boundaries must be managed by the protected foundation stack")
	}
	if stack.TerminationProtection() == nil || !*stack.TerminationProtection() {
		t.Fatal("IAM foundation lacks termination protection")
	}
}

func TestBackendRolesReceiveImmutableRuntimeBoundaryOutsideLocalStack(t *testing.T) {
	t.Setenv("PDF_USE_DEDICATED_EXECUTION_ROLE", "1")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("BoundaryTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
	applyRuntimeBoundary(stack, "111111111111", false)
	// A role created after applying the aspect must synthesize the imported
	// boundary; the aspect also covers Lambda/ECS roles created by main.go.
	awsiam.NewRole(stack, jsii.String("RuntimeRole"), &awsiam.RoleProps{AssumedBy: awsiam.NewServicePrincipal(jsii.String("ecs-tasks.amazonaws.com"), nil)})
	template := assertions.Template_FromStack(stack, nil)
	template.HasResourceProperties(jsii.String("AWS::IAM::Role"), map[string]any{
		"PermissionsBoundary": "arn:aws:iam::111111111111:policy/" + runtimeBoundaryName,
	})
}

func TestLegacyDeployDoesNotReferenceBoundaryBeforeFoundationExists(t *testing.T) {
	t.Setenv("PDF_USE_DEDICATED_EXECUTION_ROLE", "0")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("LegacyBoundaryTest"), nil)
	applyRuntimeBoundary(stack, "111111111111", false)
	awsiam.NewRole(stack, jsii.String("RuntimeRole"), &awsiam.RoleProps{AssumedBy: awsiam.NewServicePrincipal(jsii.String("ecs-tasks.amazonaws.com"), nil)})
	resources := (*assertions.Template_FromStack(stack, nil).ToJSON())["Resources"].(map[string]interface{})
	for _, raw := range resources {
		resource := raw.(map[string]interface{})
		if resource["Type"] == "AWS::IAM::Role" {
			if _, exists := resource["Properties"].(map[string]interface{})["PermissionsBoundary"]; exists {
				t.Fatal("legacy deployment references a boundary before foundation creation")
			}
		}
	}
}

func TestNetworkDeploymentCannotAdoptOrNestInsideUnownedResources(t *testing.T) {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("NetworkPolicyTest"), nil)
	statements := networkDeploymentStatements("111111111111", "us-east-2")
	awsiam.NewManagedPolicy(stack, jsii.String("Policy"), &awsiam.ManagedPolicyProps{
		ManagedPolicyName: jsii.String("PDF_NETWORK_DEPLOY"), Statements: &statements,
	})
	resources := (*assertions.Template_FromStack(stack, nil).ToJSON())["Resources"].(map[string]interface{})
	var policyStatements []interface{}
	for _, raw := range resources {
		resource := raw.(map[string]interface{})
		if resource["Type"] != "AWS::IAM::ManagedPolicy" {
			continue
		}
		properties := resource["Properties"].(map[string]interface{})
		if properties["ManagedPolicyName"] == "PDF_NETWORK_DEPLOY" {
			policyStatements = properties["PolicyDocument"].(map[string]interface{})["Statement"].([]interface{})
		}
	}
	if policyStatements == nil {
		t.Fatal("network deployment policy missing")
	}
	vpc := "arn:aws:ec2:us-east-2:111111111111:vpc/vpc-unowned"
	subnet := "arn:aws:ec2:us-east-2:111111111111:subnet/subnet-new"
	if simulatedNetworkAllow(policyStatements, "ec2:CreateTags", vpc, "agent-pdf", "", "") {
		t.Fatal("an unowned VPC can be adopted with a standalone CreateTags call")
	}
	if !simulatedNetworkAllow(policyStatements, "ec2:CreateTags", vpc, "agent-pdf", "", "CreateVpc") {
		t.Fatal("tag-on-create authorization is missing for a new PDF VPC")
	}
	if !simulatedNetworkAllow(policyStatements, "ec2:CreateTags", vpc, "", "agent-pdf", "") {
		t.Fatal("an already-owned VPC cannot receive ordinary tag maintenance")
	}
	if !simulatedNetworkAllow(policyStatements, "ec2:CreateSubnet", subnet, "agent-pdf", "", "") {
		t.Fatal("new tagged PDF subnet resource is not authorized")
	}
	if simulatedNetworkAllow(policyStatements, "ec2:CreateSubnet", vpc, "agent-pdf", "", "") {
		t.Fatal("a PDF subnet can be created inside an unowned parent VPC")
	}
	if !simulatedNetworkAllow(policyStatements, "ec2:CreateSubnet", vpc, "agent-pdf", "agent-pdf", "") {
		t.Fatal("a PDF subnet cannot be created inside its owned parent VPC")
	}
}

func simulatedNetworkAllow(statements []interface{}, action, resource, requestProject, resourceProject, createAction string) bool {
	for _, raw := range statements {
		statement := raw.(map[string]interface{})
		if !jsonValueContains(statement["Action"], action) || !jsonResourceMatches(statement["Resource"], resource) {
			continue
		}
		conditions, _ := statement["Condition"].(map[string]interface{})
		stringEquals, _ := conditions["StringEquals"].(map[string]interface{})
		if required, exists := stringEquals["aws:RequestTag/Project"]; exists && required != requestProject {
			continue
		}
		if required, exists := stringEquals["aws:ResourceTag/Project"]; exists && required != resourceProject {
			continue
		}
		if allowed, exists := stringEquals["ec2:CreateAction"]; exists && !jsonValueContains(allowed, createAction) {
			continue
		}
		return true
	}
	return false
}

func jsonValueContains(raw any, wanted string) bool {
	switch value := raw.(type) {
	case string:
		return value == wanted
	case []interface{}:
		for _, item := range value {
			if item == wanted {
				return true
			}
		}
	}
	return false
}

func jsonResourceMatches(raw any, resource string) bool {
	values := []string{}
	switch value := raw.(type) {
	case string:
		values = append(values, value)
	case []interface{}:
		for _, item := range value {
			values = append(values, item.(string))
		}
	}
	for _, pattern := range values {
		if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*")) {
			return true
		}
		if pattern == resource {
			return true
		}
	}
	return false
}
