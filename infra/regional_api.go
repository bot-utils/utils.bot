package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscertificatemanager"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsroute53"
	"github.com/aws/aws-cdk-go/awscdk/v2/awswafv2"
	"github.com/aws/jsii-runtime-go"
	"os"
)

const regionalAPIHost = "api." + domain

func directAPIEnabled() bool {
	switch os.Getenv("PDF_DIRECT_API") {
	case "", "0":
		return false
	case "1":
		return true
	default:
		panic("PDF_DIRECT_API must be 0 or 1")
	}
}

// The origin keeps a CloudFront-only network port when regional API ingress opens.
func originHTTPSPort() float64 {
	if directAPIEnabled() {
		return 8443
	}
	return 443
}
func regionalAPI(stack awscdk.Stack, alb awselasticloadbalancingv2.ApplicationLoadBalancer, targets awselasticloadbalancingv2.ApplicationTargetGroup, origin awselasticloadbalancingv2.ApplicationListener) {
	zone := awsroute53.HostedZone_FromHostedZoneAttributes(stack, jsii.String("ApiZone"), &awsroute53.HostedZoneAttributes{HostedZoneId: jsii.String(hostedZoneID()), ZoneName: jsii.String(domain)})
	cert := awscertificatemanager.NewCertificate(stack, jsii.String("ApiCertificate"), &awscertificatemanager.CertificateProps{DomainName: jsii.String(regionalAPIHost), Validation: awscertificatemanager.CertificateValidation_FromDns(zone)})
	listener := alb.AddListener(jsii.String("RegionalApi"), &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(443), Open: jsii.Bool(false), Certificates: &[]awselasticloadbalancingv2.IListenerCertificate{awselasticloadbalancingv2.ListenerCertificate_FromCertificateManager(cert)}, SslPolicy: awselasticloadbalancingv2.SslPolicy_TLS13_RES, DefaultAction: awselasticloadbalancingv2.ListenerAction_FixedResponse(jsii.Number(404), &awselasticloadbalancingv2.FixedResponseOptions{ContentType: jsii.String("application/json"), MessageBody: jsii.String(`{"error":"not_found"}`)})})
	// Free the legacy origin's 443 listener before creating the API listener.
	// Depend only on the listener resource, not its target/service descendants.
	listener.Node().DefaultChild().(awscdk.CfnResource).AddDependency(origin.Node().DefaultChild().(awscdk.CfnResource))
	listener.AddAction(jsii.String("PaidPDF"), &awselasticloadbalancingv2.AddApplicationActionProps{Priority: jsii.Number(10), Conditions: &[]awselasticloadbalancingv2.ListenerCondition{awselasticloadbalancingv2.ListenerCondition_HostHeaders(jsii.Strings(regionalAPIHost)), awselasticloadbalancingv2.ListenerCondition_PathPatterns(jsii.Strings("/v1/pdf/text")), awselasticloadbalancingv2.ListenerCondition_HttpRequestMethods(jsii.Strings("POST", "OPTIONS"))}, Action: awselasticloadbalancingv2.ListenerAction_Forward(&[]awselasticloadbalancingv2.IApplicationTargetGroup{targets}, nil)})
	awsroute53.NewCfnRecordSet(stack, jsii.String("ApiDomain"), &awsroute53.CfnRecordSetProps{HostedZoneId: jsii.String(hostedZoneID()), Name: jsii.String(regionalAPIHost), Type: jsii.String("A"), AliasTarget: &awsroute53.CfnRecordSet_AliasTargetProperty{DnsName: alb.LoadBalancerDnsName(), HostedZoneId: alb.LoadBalancerCanonicalHostedZoneId(), EvaluateTargetHealth: jsii.Bool(false)}})
	regionalAPIProtection(stack, alb)
	awscdk.NewCfnOutput(stack, jsii.String("ApiCertificateArn"), &awscdk.CfnOutputProps{Value: cert.CertificateArn()})
}
func regionalAPIProtection(stack awscdk.Stack, alb awselasticloadbalancingv2.ApplicationLoadBalancer) {
	visibility := func(name string) map[string]any {
		return map[string]any{"cloudWatchMetricsEnabled": true, "sampledRequestsEnabled": false, "metricName": name}
	}
	match := func(field, value string) map[string]any {
		return map[string]any{"byteMatchStatement": map[string]any{"fieldToMatch": map[string]any{field: map[string]any{}}, "positionalConstraint": "EXACTLY", "searchString": value, "textTransformations": []any{map[string]any{"priority": 0, "type": "NONE"}}}}
	}
	header := func(name, value, position, transform string) map[string]any {
		return map[string]any{"byteMatchStatement": map[string]any{"fieldToMatch": map[string]any{"singleHeader": map[string]any{"Name": name}}, "positionalConstraint": position, "searchString": value, "textTransformations": []any{map[string]any{"priority": 0, "type": transform}}}}
	}
	and := func(statements ...any) map[string]any {
		return map[string]any{"andStatement": map[string]any{"statements": statements}}
	}
	not := func(statement any) map[string]any {
		return map[string]any{"notStatement": map[string]any{"statement": statement}}
	}
	present := func(name string) map[string]any {
		return map[string]any{"sizeConstraintStatement": map[string]any{"fieldToMatch": map[string]any{"singleHeader": map[string]any{"Name": name}}, "comparisonOperator": "GT", "size": 0, "textTransformations": []any{map[string]any{"priority": 0, "type": "NONE"}}}}
	}
	apiScope := map[string]any{"orStatement": map[string]any{"statements": []any{header("host", regionalAPIHost, "EXACTLY", "LOWERCASE"), header("host", regionalAPIHost+":443", "EXACTLY", "LOWERCASE")}}}
	pdfPath := match("uriPath", "/v1/pdf/text")
	pdfPost := and(apiScope, pdfPath, match("method", "POST"))
	response := func(code int, key string, headers ...any) map[string]any {
		return map[string]any{"block": map[string]any{"customResponse": map[string]any{"responseCode": code, "customResponseBodyKey": key, "responseHeaders": append([]any{map[string]any{"name": "Cache-Control", "value": "no-store"}}, headers...)}}}
	}
	rules := []any{
		map[string]any{"name": "GeographicAccessPolicy", "priority": 0, "statement": and(apiScope, geographicStatement()), "action": response(403, "locationDenied"), "visibilityConfig": visibility("agent-pdf-api-geography")},
		map[string]any{"name": "ApiMethods", "priority": 1, "statement": and(apiScope, pdfPath, not(map[string]any{"orStatement": map[string]any{"statements": []any{match("method", "POST"), match("method", "OPTIONS")}}})), "action": response(405, "methodDenied", map[string]any{"name": "Allow", "value": "POST, OPTIONS"}), "visibilityConfig": visibility("agent-pdf-api-methods")},
		// A coarse prefilter; Go retains exact header, media, size and payment checks.
		map[string]any{"name": "ApiContentHeaders", "priority": 2, "statement": and(apiScope, pdfPath, match("method", "POST"), present("payment-signature"), map[string]any{"orStatement": map[string]any{"statements": []any{not(header("content-type", "application/pdf", "STARTS_WITH", "LOWERCASE")), and(present("content-encoding"), not(header("content-encoding", "identity", "EXACTLY", "NONE")))}}}), "action": response(415, "contentDenied"), "visibilityConfig": visibility("agent-pdf-api-content")},
	}
	for i, limit := range []struct {
		name, key string
		value     int
		scope     any
	}{{"PerIpRequestRate", "IP", 300, apiScope}, {"GlobalRequestRate", "CONSTANT", 1000, apiScope}, {"GlobalPdfPostRate", "CONSTANT", 120, pdfPost}} {
		rules = append(rules, map[string]any{"name": limit.name, "priority": i + 3, "statement": map[string]any{"rateBasedStatement": map[string]any{"limit": limit.value, "evaluationWindowSec": 60, "aggregateKeyType": limit.key, "scopeDownStatement": limit.scope}}, "action": response(429, "rateLimited", map[string]any{"name": "Retry-After", "value": "60"}), "visibilityConfig": visibility("agent-pdf-api-" + limit.name)})
	}
	acl := awswafv2.NewCfnWebACL(stack, jsii.String("TrafficProtection"), &awswafv2.CfnWebACLProps{Name: jsii.String("agent-pdf-mock"), Scope: jsii.String("REGIONAL"), DefaultAction: map[string]any{"allow": map[string]any{}}, VisibilityConfig: visibility("agent-pdf-api"), Rules: rules, CustomResponseBodies: map[string]any{"locationDenied": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"location_not_supported"}`}, "methodDenied": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"method_not_allowed"}`}, "contentDenied": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"invalid_content_headers"}`}, "rateLimited": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"rate_limited"}`}}})
	awswafv2.NewCfnWebACLAssociation(stack, jsii.String("TrafficProtectionAssociation"), &awswafv2.CfnWebACLAssociationProps{ResourceArn: alb.LoadBalancerArn(), WebAclArn: acl.AttrArn()})
	awscdk.NewCfnOutput(stack, jsii.String("WebAclArn"), &awscdk.CfnOutputProps{Value: acl.AttrArn()})
}
