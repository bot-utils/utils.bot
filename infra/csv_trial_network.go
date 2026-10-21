package main

import (
	"regexp"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

// Preparation only: this independent stack has no jobs, IAM resources, assets,
// NAT, public addressing, peering, or connection to the live service VPC.
func csvTrialNetworkStack(app awscdk.App, account, az, s3PrefixList string, paidEndpoints bool) awscdk.Stack {
	if !regexp.MustCompile(`^us-east-2[a-c]$`).MatchString(az) ||
		!regexp.MustCompile(`^pl-[a-f0-9]{8,17}$`).MatchString(s3PrefixList) {
		panic("CSV trial requires an Ohio availability zone and verified regional S3 prefix list")
	}
	// The caller chooses one verified zone; avoid account-wide AZ lookups.
	app.Node().SetContext(jsii.String("availability-zones:account="+account+":region=us-east-2"), []string{az})
	stack := awscdk.NewStack(app, jsii.String("UtilsBotCsvTrialNetwork"), &awscdk.StackProps{
		Env:         &awscdk.Environment{Account: jsii.String(account), Region: jsii.String("us-east-2")},
		Description: jsii.String("Disposable private network for synthetic CSV backend comparison"),
		Synthesizer: newAssetFreeSynthesizer(namedRoleArn(account, "utils-bot-csv-trial-network-execution")),
	})
	awscdk.Tags_Of(stack).Add(jsii.String("Project"), jsii.String("utils-bot"), nil)
	awscdk.Tags_Of(stack).Add(jsii.String("Purpose"), jsii.String("utils-bot-csv-trial"), nil)

	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{
		IpAddresses:       awsec2.IpAddresses_Cidr(jsii.String("10.88.0.0/24")),
		AvailabilityZones: &[]*string{jsii.String(az)},
		NatGateways:       jsii.Number(0), EnableDnsHostnames: jsii.Bool(true), EnableDnsSupport: jsii.Bool(true),
		RestrictDefaultSecurityGroup: jsii.Bool(false),
		SubnetConfiguration: &[]*awsec2.SubnetConfiguration{{
			Name: jsii.String("isolated"), CidrMask: jsii.Number(25),
			SubnetType: awsec2.SubnetType_PRIVATE_ISOLATED,
		}},
	})
	parser := awsec2.NewSecurityGroup(stack, jsii.String("Fargate"), &awsec2.SecurityGroupProps{
		Vpc: vpc, AllowAllOutbound: jsii.Bool(false), Description: jsii.String("Credentialless synthetic Fargate tasks only"),
	})
	glue := awsec2.NewSecurityGroup(stack, jsii.String("Glue"), &awsec2.SecurityGroupProps{
		Vpc: vpc, AllowAllOutbound: jsii.Bool(false), Description: jsii.String("Synthetic Glue jobs only; never customer content"),
	})
	// Glue's VPC admission requires a self-referencing TCP rule. This group
	// is separate from Fargate; admission permits only one comparison job.
	glue.AddIngressRule(glue, awsec2.Port_AllTcp(), jsii.String("Glue self-traffic only"), nil)
	glue.AddEgressRule(glue, awsec2.Port_AllTcp(), jsii.String("Glue self-traffic only"), nil)
	endpoints := awsec2.NewSecurityGroup(stack, jsii.String("Endpoints"), &awsec2.SecurityGroupProps{
		Vpc: vpc, AllowAllOutbound: jsii.Bool(false), Description: jsii.String("Private AWS service endpoints only"),
	})
	for _, worker := range []awsec2.SecurityGroup{parser, glue} {
		endpoints.AddIngressRule(worker, awsec2.Port_Tcp(jsii.Number(443)), jsii.String("Private service HTTPS"), nil)
		worker.AddEgressRule(endpoints, awsec2.Port_Tcp(jsii.Number(443)), jsii.String("Private service HTTPS"), nil)
		worker.AddEgressRule(awsec2.Peer_PrefixList(jsii.String(s3PrefixList)), awsec2.Port_Tcp(jsii.Number(443)), jsii.String("Regional S3 gateway only"), nil)
	}

	execution := namedRoleArn(account, "utils-bot-csv-trial-ecs-execution")
	glueRole := namedRoleArn(account, "utils-bot-csv-trial-glue")
	bucket := "utils-bot-csv-trial-" + account + "-us-east-2"
	repository := "arn:aws:ecr:us-east-2:" + account + ":repository/utils-bot-csv-trial"
	group := "arn:aws:logs:us-east-2:" + account + ":log-group:/utils-bot/csv-trial:log-stream:*"
	s3 := vpc.AddGatewayEndpoint(jsii.String("S3"), &awsec2.GatewayVpcEndpointOptions{
		Service: awsec2.GatewayVpcEndpointAwsService_S3(),
		Subnets: &[]*awsec2.SubnetSelection{{SubnetType: awsec2.SubnetType_PRIVATE_ISOLATED}},
	})
	s3.AddToPolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Principals: &[]awsiam.IPrincipal{awsiam.NewAnyPrincipal()}, Actions: jsii.Strings("s3:GetObject"),
		Resources: jsii.Strings("arn:aws:s3:::prod-us-east-2-starport-layer-bucket/*"),
	}))
	s3.AddToPolicy(trialEndpointStatement(glueRole, []string{"s3:GetObject"}, []string{"arn:aws:s3:::" + bucket + "/trial/code/*"}))

	services := []struct {
		id      string
		service awsec2.IInterfaceVpcEndpointService
	}{
		{"EcrApi", awsec2.InterfaceVpcEndpointAwsService_ECR()},
		{"EcrDocker", awsec2.InterfaceVpcEndpointAwsService_ECR_DOCKER()},
		{"Logs", awsec2.InterfaceVpcEndpointAwsService_CLOUDWATCH_LOGS()},
	}
	for _, service := range services {
		if !paidEndpoints {
			continue
		}
		endpoint := vpc.AddInterfaceEndpoint(jsii.String(service.id), &awsec2.InterfaceVpcEndpointOptions{
			Service: service.service, Open: jsii.Bool(false), PrivateDnsEnabled: jsii.Bool(true),
			SecurityGroups:     &[]awsec2.ISecurityGroup{endpoints},
			Subnets:            &awsec2.SubnetSelection{SubnetType: awsec2.SubnetType_PRIVATE_ISOLATED},
			LookupSupportedAzs: jsii.Bool(false),
		})
		if service.id == "Logs" {
			endpoint.AddToPolicy(trialEndpointStatement(execution, []string{"logs:CreateLogStream", "logs:PutLogEvents"}, []string{group}))
			// Python shell uses these service-defined groups; do not assume
			// Spark's custom logging arguments apply to Python shell.
			endpoint.AddToPolicy(trialEndpointStatement(glueRole, []string{"logs:CreateLogStream", "logs:PutLogEvents"}, []string{
				"arn:aws:logs:us-east-2:" + account + ":log-group:/aws-glue/python-jobs/output:log-stream:*",
				"arn:aws:logs:us-east-2:" + account + ":log-group:/aws-glue/python-jobs/error:log-stream:*",
			}))
		} else {
			endpoint.AddToPolicy(trialEndpointStatement(execution, []string{"ecr:GetAuthorizationToken"}, []string{"*"}))
			endpoint.AddToPolicy(trialEndpointStatement(execution, []string{"ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"}, []string{repository}))
		}
	}

	tags := []map[string]string{{"Key": "Project", "Value": "utils-bot"}, {"Key": "Purpose", "Value": "utils-bot-csv-trial"}}
	domains := []string{
		"api.ecr.us-east-2.amazonaws.com", account + ".dkr.ecr.us-east-2.amazonaws.com",
		"logs.us-east-2.amazonaws.com", "s3.us-east-2.amazonaws.com",
		bucket + ".s3.us-east-2.amazonaws.com",
		"prod-us-east-2-starport-layer-bucket.s3.us-east-2.amazonaws.com",
	}
	allow := awscdk.NewCfnResource(stack, jsii.String("AllowedDnsNames"), &awscdk.CfnResourceProps{
		Type:       jsii.String("AWS::Route53Resolver::FirewallDomainList"),
		Properties: &map[string]interface{}{"Name": "utils-bot-csv-trial-allow", "Domains": domains, "Tags": tags},
	})
	block := awscdk.NewCfnResource(stack, jsii.String("BlockedDnsNames"), &awscdk.CfnResourceProps{
		Type:       jsii.String("AWS::Route53Resolver::FirewallDomainList"),
		Properties: &map[string]interface{}{"Name": "utils-bot-csv-trial-block", "Domains": []string{"*"}, "Tags": tags},
	})
	firewall := awscdk.NewCfnResource(stack, jsii.String("DnsFirewall"), &awscdk.CfnResourceProps{
		Type: jsii.String("AWS::Route53Resolver::FirewallRuleGroup"),
		Properties: &map[string]interface{}{
			"Name": "utils-bot-csv-trial", "Tags": tags,
			"FirewallRules": []interface{}{
				map[string]interface{}{"Action": "ALLOW", "Priority": 100, "FirewallDomainListId": allow.Ref(), "FirewallDomainRedirectionAction": "INSPECT_REDIRECTION_DOMAIN"},
				map[string]interface{}{"Action": "BLOCK", "Priority": 200, "FirewallDomainListId": block.Ref(), "BlockResponse": "NODATA", "FirewallDomainRedirectionAction": "INSPECT_REDIRECTION_DOMAIN"},
			},
		},
	})
	association := awscdk.NewCfnResource(stack, jsii.String("DnsAssociation"), &awscdk.CfnResourceProps{
		Type: jsii.String("AWS::Route53Resolver::FirewallRuleGroupAssociation"),
		Properties: &map[string]interface{}{
			"Name": "utils-bot-csv-trial", "Tags": tags, "VpcId": vpc.VpcId(),
			"FirewallRuleGroupId": firewall.Ref(), "Priority": 100, "MutationProtection": "DISABLED",
		},
	})
	association.AddDependency(firewall)
	for name, value := range map[string]*string{
		"TrialVpc": vpc.VpcId(), "TrialDefaultSecurityGroup": vpc.VpcDefaultSecurityGroup(), "TrialSubnet": (*vpc.IsolatedSubnets())[0].SubnetId(),
		"FargateSecurityGroup": parser.SecurityGroupId(), "GlueSecurityGroup": glue.SecurityGroupId(),
		"EndpointSecurityGroup": endpoints.SecurityGroupId(),
	} {
		awscdk.NewCfnOutput(stack, jsii.String(name), &awscdk.CfnOutputProps{Value: value})
	}
	// No job may use the unused AWS default SG. A post-create hardening step
	// must revoke both default rule sets and verify emptiness, using its exact
	// output ID; avoid introducing a privileged Lambda provider just for this.
	// The provider DNS default is fail-closed. Deployment admission must read
	// GetFirewallConfig and verify FirewallFailOpen=DISABLED before any job.
	return stack
}

func trialEndpointStatement(role string, actions, resources []string) awsiam.PolicyStatement {
	return awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Principals: &[]awsiam.IPrincipal{awsiam.NewAnyPrincipal()},
		Actions:    jsii.Strings(actions...), Resources: jsii.Strings(resources...),
		Conditions: &map[string]interface{}{"ArnEquals": map[string]interface{}{"aws:PrincipalArn": role}},
	})
}
