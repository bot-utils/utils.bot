package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
)

func TestCsvTrialNetworkHasOnlyPrivatePathsAndScopedEndpoints(t *testing.T) {
	app := awscdk.NewApp(nil)
	stack := csvTrialNetworkStack(app, "111111111111", "us-east-2a", "pl-f00dcafe", true)
	template := assertions.Template_FromStack(stack, nil)
	for _, kind := range []string{"AWS::EC2::InternetGateway", "AWS::EC2::NatGateway", "AWS::EC2::EgressOnlyInternetGateway", "AWS::EC2::VPCPeeringConnection", "AWS::EC2::Route", "AWS::ECS::Service", "AWS::ECS::TaskDefinition", "AWS::Glue::Job", "AWS::IAM::Role", "AWS::Lambda::Function"} {
		template.ResourceCountIs(jsii.String(kind), jsii.Number(0))
	}
	template.ResourceCountIs(jsii.String("AWS::EC2::VPC"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::EC2::Subnet"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::EC2::VPCEndpoint"), jsii.Number(4))
	template.HasResourceProperties(jsii.String("AWS::EC2::Subnet"), map[string]any{"MapPublicIpOnLaunch": false, "AvailabilityZone": "us-east-2a"})
	resources := (*template.ToJSON())["Resources"].(map[string]any)
	interfaces, gateways := 0, 0
	for _, raw := range resources {
		r := raw.(map[string]any)
		p, _ := r["Properties"].(map[string]any)
		switch r["Type"] {
		case "AWS::EC2::VPCEndpoint":
			doc, _ := json.Marshal(p["PolicyDocument"])
			if p["VpcEndpointType"] == "Interface" {
				interfaces++
				if p["PrivateDnsEnabled"] != true || !strings.Contains(string(doc), "aws:PrincipalArn") {
					t.Fatal("interface endpoint lost private DNS or role scope")
				}
			} else if p["VpcEndpointType"] == "Gateway" {
				gateways++
				for _, marker := range []string{"prod-us-east-2-starport-layer-bucket", "trial/code/", "utils-bot-csv-trial-glue"} {
					if !strings.Contains(string(doc), marker) {
						t.Fatal("S3 gateway scope missing", marker)
					}
				}
				if strings.Contains(string(doc), "s3:PutObject") {
					t.Fatal("engine-only trial must not publish artifacts")
				}
			}
		case "AWS::EC2::SecurityGroupEgress":
			if p["CidrIp"] != nil || p["CidrIpv6"] != nil {
				t.Fatal("egress rule must target owned SG or S3 prefix list")
			}
		case "AWS::Route53Resolver::FirewallRuleGroup":
			rules := p["FirewallRules"].([]any)
			if len(rules) != 2 || rules[0].(map[string]any)["Action"] != "ALLOW" || rules[1].(map[string]any)["Action"] != "BLOCK" {
				t.Fatal("DNS must allow exact dependencies before default block")
			}
			for _, rawRule := range rules {
				if rawRule.(map[string]any)["FirewallDomainRedirectionAction"] != "INSPECT_REDIRECTION_DOMAIN" {
					t.Fatal("DNS redirection bypass")
				}
			}
		case "AWS::Route53Resolver::FirewallDomainList":
			domains := p["Domains"].([]any)
			for _, domain := range domains {
				value := domain.(string)
				if value != "*" && (strings.Contains(value, "*") || !strings.HasSuffix(value, ".us-east-2.amazonaws.com")) {
					t.Fatal("broad or cross-region DNS allowance", value)
				}
			}
		}
	}
	if interfaces != 3 || gateways != 1 {
		t.Fatal("unexpected endpoint standing cost", interfaces, gateways)
	}
	artifact := app.Synth(nil).GetStackArtifact(stack.ArtifactId())
	if role := artifact.CloudFormationExecutionRoleArn(); role == nil || *role != "arn:aws:iam::111111111111:role/utils-bot-csv-trial-network-execution" {
		t.Fatal("wrong network execution role", role)
	}
	if artifact.AssumeRoleArn() != nil {
		t.Fatal("network assembly must use current caller")
	}
}

func TestCsvTrialNetworkDefaultsToNoPaidInterfaceEndpoints(t *testing.T) {
	app := awscdk.NewApp(nil)
	stack := csvTrialNetworkStack(app, "111111111111", "us-east-2a", "pl-f00dcafe", false)
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::EC2::VPCEndpoint"), jsii.Number(1))
	template.HasResourceProperties(jsii.String("AWS::EC2::VPCEndpoint"), map[string]any{"VpcEndpointType": "Gateway"})
	template.HasResourceProperties(jsii.String("AWS::Route53Resolver::FirewallRuleGroupAssociation"), map[string]any{"Priority": 101})
	outputs := (*template.ToJSON())["Outputs"].(map[string]any)
	if outputs["TrialDefaultSecurityGroup"] == nil {
		t.Fatal("must expose the exact default security group for preflight hardening")
	}
}
