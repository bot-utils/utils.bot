package main

import (
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/jsii-runtime-go"
)

func TestNetworkIsRestrictedAndALBFailsClosed(t *testing.T) {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("NetworkTest"), nil)
	vpc := awsec2.NewVpc(stack, jsii.String("Vpc"), &awsec2.VpcProps{MaxAzs: jsii.Number(2), NatGateways: jsii.Number(0)})
	albSG, _, _ := networkSecurity(stack, vpc, "203.0.113.10/32")
	alb := awselasticloadbalancingv2.NewApplicationLoadBalancer(stack, jsii.String("Alb"), &awselasticloadbalancingv2.ApplicationLoadBalancerProps{Vpc: vpc, InternetFacing: jsii.Bool(true), SecurityGroup: albSG})
	hardenALB(alb, true)
	targets := awselasticloadbalancingv2.NewApplicationTargetGroup(stack, jsii.String("Targets"), &awselasticloadbalancingv2.ApplicationTargetGroupProps{Vpc: vpc, Port: jsii.Number(8080)})
	balanceBusyParsers(targets)
	resources := (*assertions.Template_FromStack(stack, nil).ToJSON())["Resources"].(map[string]interface{})
	egress, ingress := 0, 0
	attrs := map[string]string{}
	for _, raw := range resources {
		r := raw.(map[string]interface{})
		p, _ := r["Properties"].(map[string]interface{})
		switch r["Type"] {
		case "AWS::EC2::SecurityGroup":
			// CDK's default deny placeholder permits only unused ICMP to
			// 255.255.255.255; no inline allow-all rule may reappear.
			rules, _ := p["SecurityGroupEgress"].([]interface{})
			for _, raw := range rules {
				rule := raw.(map[string]interface{})
				if rule["CidrIp"] != "255.255.255.255/32" {
					t.Fatal("inline egress widened", rule)
				}
			}
		case "AWS::EC2::SecurityGroupEgress":
			egress++
			if p["IpProtocol"] != "tcp" || p["FromPort"] != p["ToPort"] {
				t.Fatal("broad egress", p)
			}
			if p["CidrIp"] == "0.0.0.0/0" {
				if p["FromPort"] != float64(443) {
					t.Fatal("internet egress is not TLS", p)
				}
			} else if p["DestinationSecurityGroupId"] == nil || p["FromPort"] != float64(8080) {
				t.Fatal("ALB egress is not task-only", p)
			}
		case "AWS::EC2::SecurityGroupIngress":
			ingress++
			if p["CidrIp"] != nil {
				if p["CidrIp"] != "203.0.113.10/32" || p["FromPort"] != float64(80) {
					t.Fatal("owner ingress widened", p)
				}
			} else if p["SourceSecurityGroupId"] == nil || p["FromPort"] != float64(8080) {
				t.Fatal("task ingress widened", p)
			}
		case "AWS::ElasticLoadBalancingV2::LoadBalancer":
			for _, raw := range p["LoadBalancerAttributes"].([]interface{}) {
				a := raw.(map[string]interface{})
				attrs[a["Key"].(string)] = a["Value"].(string)
			}
		case "AWS::ElasticLoadBalancingV2::TargetGroup":
			attributes := p["TargetGroupAttributes"].([]interface{})
			balanced := false
			for _, raw := range attributes {
				attribute := raw.(map[string]interface{})
				if attribute["Key"] == "load_balancing.algorithm.type" && attribute["Value"] == "least_outstanding_requests" {
					balanced = true
				}
			}
			if !balanced {
				t.Fatal("busy parser balancing policy changed", attributes)
			}
		}
	}
	if egress != 2 || ingress != 2 {
		t.Fatalf("unexpected rule counts: egress=%d ingress=%d", egress, ingress)
	}
	for key, value := range map[string]string{"deletion_protection.enabled": "true", "routing.http.drop_invalid_header_fields.enabled": "true", "routing.http.desync_mitigation_mode": "strictest", "waf.fail_open.enabled": "false", "routing.http.preserve_host_header.enabled": "false"} {
		if attrs[key] != value {
			t.Fatal("ALB safeguard changed", key, attrs[key])
		}
	}
}
