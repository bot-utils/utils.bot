package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/jsii-runtime-go"
	"os"
)

func networkSecurity(stack awscdk.Stack, vpc awsec2.IVpc, cidr string, edgePrefix ...string) (awsec2.SecurityGroup, awsec2.SecurityGroup, awsec2.SecurityGroup) {
	// Separate rule resources avoid cyclic group dependencies.
	alb := awsec2.NewSecurityGroup(stack, jsii.String("AlbSecurityGroup"), &awsec2.SecurityGroupProps{Vpc: vpc, AllowAllOutbound: jsii.Bool(false), DisableInlineRules: jsii.Bool(true)})
	task := awsec2.NewSecurityGroup(stack, jsii.String("TaskSecurityGroup"), &awsec2.SecurityGroupProps{Vpc: vpc, AllowAllOutbound: jsii.Bool(false), DisableInlineRules: jsii.Bool(true)})
	var origin awsec2.SecurityGroup
	if len(edgePrefix) > 0 && edgePrefix[0] != "" {
		originIngress := alb
		if directAPIEnabled() {
			// The managed CloudFront prefix list weighs 55 ingress rules. Keep
			// the new origin port in its own group so create-before-delete can
			// coexist with the old 443 rule during the regional migration.
			origin = awsec2.NewSecurityGroup(stack, jsii.String("CloudFrontOriginSecurityGroup"), &awsec2.SecurityGroupProps{Vpc: vpc, AllowAllOutbound: jsii.Bool(false), DisableInlineRules: jsii.Bool(true)})
			originIngress = origin
			peer := awsec2.Peer_Ipv4(jsii.String(cidr))
			if os.Getenv("PDF_PUBLIC_ACCESS") == "1" {
				peer = awsec2.Peer_AnyIpv4()
			}
			alb.AddIngressRule(peer, awsec2.Port_Tcp(jsii.Number(443)), jsii.String("Regional API; owner only until explicit public launch"), jsii.Bool(false))
		}
		originIngress.AddIngressRule(awsec2.Peer_PrefixList(jsii.String(edgePrefix[0])), awsec2.Port_Tcp(jsii.Number(originHTTPSPort())), jsii.String("HTTPS only from CloudFront origins"), jsii.Bool(false))
	} else {
		alb.AddIngressRule(awsec2.Peer_Ipv4(jsii.String(cidr)), awsec2.Port_Tcp(jsii.Number(80)), jsii.String("HTTP mock test access from owner IP"), jsii.Bool(false))
	}
	task.AddIngressRule(alb, awsec2.Port_Tcp(jsii.Number(8080)), jsii.String("Only ALB reaches receiver"), jsii.Bool(false))
	alb.AddEgressRule(task, awsec2.Port_Tcp(jsii.Number(8080)), jsii.String("Only receiver and health checks"), jsii.Bool(false))
	task.AddEgressRule(awsec2.Peer_AnyIpv4(), awsec2.Port_Tcp(jsii.Number(443)), jsii.String("TLS AWS APIs, image delivery and logs"), jsii.Bool(false))
	return alb, task, origin
}

func hardenALB(alb awselasticloadbalancingv2.ApplicationLoadBalancer, deletionProtection bool) {
	protection := "false"
	if deletionProtection {
		protection = "true"
	}
	alb.SetAttribute(jsii.String("deletion_protection.enabled"), jsii.String(protection))
	alb.SetAttribute(jsii.String("routing.http.drop_invalid_header_fields.enabled"), jsii.String("true"))
	alb.SetAttribute(jsii.String("routing.http.desync_mitigation_mode"), jsii.String("strictest"))
	alb.SetAttribute(jsii.String("waf.fail_open.enabled"), jsii.String("false"))
	alb.SetAttribute(jsii.String("routing.http.preserve_host_header.enabled"), jsii.String("false"))
}

func balanceBusyParsers(targets awselasticloadbalancingv2.ApplicationTargetGroup) {
	// A parser admits very little concurrent work. Prefer the task with the
	// smallest in-flight request count instead of round robin so a free task is
	// selected while another task is parsing.
	targets.SetAttribute(jsii.String("load_balancing.algorithm.type"), jsii.String("least_outstanding_requests"))
}
