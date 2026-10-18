package main

import (
	"os"
	"strings"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscertificatemanager"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudfront"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudfrontorigins"
	"github.com/aws/aws-cdk-go/awscdk/v2/awselasticloadbalancingv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsroute53"
	"github.com/aws/aws-cdk-go/awscdk/v2/awswafv2"
	"github.com/aws/jsii-runtime-go"
)

const domain = "utils.bot"

func edgePrerequisites(app awscdk.App, account string) awscdk.Stack {
	// This asset-free stack uses the existing deployment roles. No bootstrap,
	// cross-region reference provider or helper Lambda is introduced.
	synth := pdfEdgeSynthesizer(account)
	stack := awscdk.NewStack(app, jsii.String("AgentPdfEdge"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(account), Region: jsii.String("us-east-1")}, Synthesizer: synth, TerminationProtection: stackTerminationProtection(os.Getenv("PDF_LOCALSTACK") == "1")})
	awscdk.Tags_Of(stack).Add(jsii.String("Project"), jsii.String("agent-pdf"), nil)
	public := publicAccessSetting(os.Getenv("PDF_PUBLIC_ACCESS"), os.Getenv("PDF_PAYMENT_MODE"))
	cidr := os.Getenv("PDF_ALLOWED_CIDR")
	if !ownerCIDR(cidr) {
		panic("edge prerequisites require the testing owner's IPv4 /32")
	}
	owner := awswafv2.NewCfnIPSet(stack, jsii.String("TestingOwner"), &awswafv2.CfnIPSetProps{Name: jsii.String("agent-pdf-owner"), Scope: jsii.String("CLOUDFRONT"), IpAddressVersion: jsii.String("IPV4"), Addresses: &[]*string{jsii.String(cidr)}})
	cert := awscertificatemanager.NewCfnCertificate(stack, jsii.String("ViewerCertificate"), &awscertificatemanager.CfnCertificateProps{DomainName: jsii.String(domain), ValidationMethod: jsii.String("DNS"), DomainValidationOptions: []any{map[string]any{"domainName": domain, "hostedZoneId": hostedZoneID()}}})
	visibility := func(name string) map[string]any {
		return map[string]any{"cloudWatchMetricsEnabled": true, "sampledRequestsEnabled": false, "metricName": name}
	}
	match := func(field, value string) map[string]any {
		return map[string]any{"byteMatchStatement": map[string]any{"fieldToMatch": map[string]any{field: map[string]any{}}, "positionalConstraint": "EXACTLY", "searchString": value, "textTransformations": []any{map[string]any{"priority": 0, "type": "NONE"}}}}
	}
	allPaths := map[string]any{"byteMatchStatement": map[string]any{"fieldToMatch": map[string]any{"uriPath": map[string]any{}}, "positionalConstraint": "STARTS_WITH", "searchString": "/", "textTransformations": []any{map[string]any{"priority": 0, "type": "NONE"}}}}
	pdfPost := map[string]any{"andStatement": map[string]any{"statements": []any{match("method", "POST"), match("uriPath", "/v1/pdf/text")}}}
	action := map[string]any{"block": map[string]any{"customResponse": map[string]any{"responseCode": 429, "customResponseBodyKey": "rateLimited", "responseHeaders": []any{map[string]any{"name": "Retry-After", "value": "60"}}}}}
	// Denied non-owner traffic must terminate before it can consume the shared
	// rate allowance. The viewer function independently retains the same gate.
	rules := []any{map[string]any{"name": "TestingOwnerOnly", "priority": 0,
		"statement":        map[string]any{"notStatement": map[string]any{"statement": map[string]any{"ipSetReferenceStatement": map[string]any{"arn": owner.AttrArn()}}}},
		"action":           map[string]any{"block": map[string]any{"customResponse": map[string]any{"responseCode": 403, "customResponseBodyKey": "notPublic", "responseHeaders": []any{map[string]any{"name": "Cache-Control", "value": "no-store"}}}}},
		"visibilityConfig": visibility("agent-pdf-testing-owner"),
	}}
	if public {
		rules = nil
	}
	rules = append(rules, map[string]any{"name": "GeographicAccessPolicy", "priority": 1,
		"statement": geographicStatement(), "action": map[string]any{"block": map[string]any{"customResponse": map[string]any{"responseCode": 403, "customResponseBodyKey": "locationDenied", "responseHeaders": []any{map[string]any{"name": "Cache-Control", "value": "no-store"}}}}},
		"visibilityConfig": visibility("agent-pdf-geography"),
	})
	for priority, rule := range []struct {
		name, key string
		limit     int
		scope     map[string]any
	}{{"PerIpRequestRate", "IP", 300, allPaths}, {"GlobalRequestRate", "CONSTANT", 1000, allPaths}, {"GlobalPdfPostRate", "CONSTANT", 120, pdfPost}} {
		rules = append(rules, map[string]any{"name": rule.name, "priority": priority + 2, "action": action, "statement": map[string]any{"rateBasedStatement": map[string]any{"aggregateKeyType": rule.key, "evaluationWindowSec": 60, "limit": rule.limit, "scopeDownStatement": rule.scope}}, "visibilityConfig": visibility("agent-pdf-edge-" + rule.name)})
	}
	acl := awswafv2.NewCfnWebACL(stack, jsii.String("TrafficProtection"), &awswafv2.CfnWebACLProps{Name: jsii.String("agent-pdf-edge"), Scope: jsii.String("CLOUDFRONT"), DefaultAction: map[string]any{"allow": map[string]any{}}, VisibilityConfig: visibility("agent-pdf-edge"), Rules: rules, CustomResponseBodies: map[string]any{"locationDenied": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"location_not_supported"}`}, "rateLimited": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"rate_limited"}`}, "notPublic": map[string]any{"contentType": "APPLICATION_JSON", "content": `{"error":"not_public"}`}}})
	awscdk.NewCfnOutput(stack, jsii.String("PublicAccessEnabled"), &awscdk.CfnOutputProps{Value: jsii.String(boolSetting(public))})
	awscdk.NewCfnOutput(stack, jsii.String("ViewerCertificateArn"), &awscdk.CfnOutputProps{Value: cert.Ref()})
	awscdk.NewCfnOutput(stack, jsii.String("EdgeWebAclArn"), &awscdk.CfnOutputProps{Value: acl.AttrArn()})
	return stack
}

func edgeDistribution(stack awscdk.Stack, originToken, viewerCert, webACL, code *string) awscloudfront.Distribution {
	var function awscloudfront.Function
	if !staticSiteEnabled() {
		function = awscloudfront.NewFunction(stack, jsii.String("FrontDoor"), &awscloudfront.FunctionProps{FunctionName: jsii.String("agent-pdf-frontdoor"), Runtime: awscloudfront.FunctionRuntime_JS_2_0(), Code: awscloudfront.FunctionCode_FromInline(code), AutoPublish: jsii.Bool(true), Comment: jsii.String("x402 quote, static introduction and exact route/method admission; no body access")})
	}
	origin := awscloudfrontorigins.NewHttpOrigin(jsii.String("origin."+domain), &awscloudfrontorigins.HttpOriginProps{HttpsPort: jsii.Number(originHTTPSPort()), ProtocolPolicy: awscloudfront.OriginProtocolPolicy_HTTPS_ONLY, CustomHeaders: &map[string]*string{"X-Agent-Pdf-Origin": originToken}, OriginSslProtocols: &[]awscloudfront.OriginSslPolicy{awscloudfront.OriginSslPolicy_TLS_V1_2}, ConnectionAttempts: jsii.Number(1), ReadTimeout: awscdk.Duration_Seconds(jsii.Number(60)), ResponseCompletionTimeout: awscdk.Duration_Seconds(jsii.Number(95))})
	forward := awscloudfront.NewOriginRequestPolicy(stack, jsii.String("OriginHeaders"), &awscloudfront.OriginRequestPolicyProps{OriginRequestPolicyName: jsii.String("agent-pdf-origin-headers"), HeaderBehavior: awscloudfront.OriginRequestHeaderBehavior_AllowList(jsii.String("Accept"), jsii.String("Content-Type"), jsii.String("Content-Encoding"), jsii.String("PAYMENT-SIGNATURE")), CookieBehavior: awscloudfront.OriginRequestCookieBehavior_None(), QueryStringBehavior: awscloudfront.OriginRequestQueryStringBehavior_None()})
	if staticSiteEnabled() {
		return staticSiteDistribution(stack, origin, viewerCert, webACL)
	}
	behavior := func(cached bool) *awscloudfront.BehaviorOptions {
		policy := awscloudfront.CachePolicy_CACHING_DISABLED()
		if cached {
			policy = awscloudfront.CachePolicy_CACHING_OPTIMIZED()
		}
		return &awscloudfront.BehaviorOptions{Origin: origin, AllowedMethods: awscloudfront.AllowedMethods_ALLOW_ALL(), CachedMethods: awscloudfront.CachedMethods_CACHE_GET_HEAD(), CachePolicy: policy, OriginRequestPolicy: forward, ViewerProtocolPolicy: awscloudfront.ViewerProtocolPolicy_HTTPS_ONLY, FunctionAssociations: &[]*awscloudfront.FunctionAssociation{{Function: function, EventType: awscloudfront.FunctionEventType_VIEWER_REQUEST}}}
	}
	additional := map[string]*awscloudfront.BehaviorOptions{}
	for _, path := range []string{"/assets/*", "/readme", "/openapi", "/openapi/json", "/openapi.yaml", "/openapi.json", "/agents", "/disclaimers", "/docs", "/llms.txt", "/robots.txt", "/sitemap.xml"} {
		additional[path] = behavior(true)
	}
	// These independent, small functions serve immutable Markdown directly.
	// They retain their own owner gate; no S3 origin or helper Lambda is used.
	for _, route := range []string{"info", "terms", "discovery"} {
		staticCode, err := os.ReadFile(os.Getenv("PDF_STATIC_" + strings.ToUpper(route) + "_CODE_FILE"))
		if err != nil {
			panic(err)
		}
		static := awscloudfront.NewFunction(stack, jsii.String("Static"+route), &awscloudfront.FunctionProps{
			FunctionName: jsii.String("agent-pdf-" + route), Runtime: awscloudfront.FunctionRuntime_JS_2_0(),
			Code: awscloudfront.FunctionCode_FromInline(jsii.String(string(staticCode))), AutoPublish: jsii.Bool(true),
			Comment: jsii.String("Owner-only static Markdown; no origin or body access"),
		})
		paths := []string{"/" + route}
		if route == "discovery" {
			paths = []string{"/robots.txt", "/sitemap.xml", "/llms.txt", "/.well-known/security.txt"}
		}
		for _, path := range paths {
			additional[path] = behavior(true)
			additional[path].FunctionAssociations = &[]*awscloudfront.FunctionAssociation{{Function: static, EventType: awscloudfront.FunctionEventType_VIEWER_REQUEST}}
		}
	}
	errors := []*awscloudfront.ErrorResponse{}
	for _, status := range []float64{403, 404, 500, 502, 503, 504} {
		errors = append(errors, &awscloudfront.ErrorResponse{HttpStatus: jsii.Number(status), Ttl: awscdk.Duration_Seconds(jsii.Number(0))})
	}
	distribution := awscloudfront.NewDistribution(stack, jsii.String("Frontend"), &awscloudfront.DistributionProps{PriceClass: awscloudfront.PriceClass_PRICE_CLASS_100, DefaultBehavior: behavior(false), AdditionalBehaviors: &additional, DomainNames: &[]*string{jsii.String(domain)}, Certificate: awscertificatemanager.Certificate_FromCertificateArn(stack, jsii.String("ViewerCertificate"), viewerCert), WebAclId: webACL, MinimumProtocolVersion: awscloudfront.SecurityPolicyProtocol_TLS_V1_2_2021, EnableIpv6: jsii.Bool(false), EnableLogging: jsii.Bool(false), GeoRestriction: awscloudfront.GeoRestriction_Denylist((*jsii.Strings(cloudFrontBlockedCountries()...))...), ErrorResponses: &errors, Comment: jsii.String("Agent tools; private by default until deliberate public launch")})
	awsroute53.NewCfnRecordSet(stack, jsii.String("PublicDomain"), &awsroute53.CfnRecordSetProps{HostedZoneId: jsii.String(hostedZoneID()), Name: jsii.String(domain), Type: jsii.String("A"), AliasTarget: &awsroute53.CfnRecordSet_AliasTargetProperty{DnsName: distribution.DistributionDomainName(), HostedZoneId: jsii.String("Z2FDTNDATAQYW2"), EvaluateTargetHealth: jsii.Bool(false)}})
	awscdk.NewCfnOutput(stack, jsii.String("CloudFrontDistributionId"), &awscdk.CfnOutputProps{Value: distribution.DistributionId()})
	awscdk.NewCfnOutput(stack, jsii.String("CloudFrontDomain"), &awscdk.CfnOutputProps{Value: distribution.DistributionDomainName()})
	awscdk.NewCfnOutput(stack, jsii.String("EdgeWebAclArn"), &awscdk.CfnOutputProps{Value: webACL})
	return distribution
}

func requiredEdgeValue(name, prefix string) string {
	value := os.Getenv(name)
	if !strings.HasPrefix(value, prefix) {
		panic("missing or invalid " + name)
	}
	return value
}

func edgeOrigin(stack awscdk.Stack, alb awselasticloadbalancingv2.ApplicationLoadBalancer, enabled bool) (*string, awscertificatemanager.Certificate) {
	if !enabled {
		return nil, nil
	}
	token := awscdk.NewCfnParameter(stack, jsii.String("OriginAuthToken"), &awscdk.CfnParameterProps{Type: jsii.String("String"), NoEcho: jsii.Bool(true), AllowedPattern: jsii.String("[0-9a-f]{64}"), MinLength: jsii.Number(64), MaxLength: jsii.Number(64)}).ValueAsString()
	zone := awsroute53.HostedZone_FromHostedZoneAttributes(stack, jsii.String("DomainZone"), &awsroute53.HostedZoneAttributes{HostedZoneId: jsii.String(hostedZoneID()), ZoneName: jsii.String(domain)})
	cert := awscertificatemanager.NewCertificate(stack, jsii.String("OriginCertificate"), &awscertificatemanager.CertificateProps{DomainName: jsii.String("origin." + domain), Validation: awscertificatemanager.CertificateValidation_FromDns(zone)})
	awsroute53.NewCfnRecordSet(stack, jsii.String("OriginDomain"), &awsroute53.CfnRecordSetProps{HostedZoneId: jsii.String(hostedZoneID()), Name: jsii.String("origin." + domain), Type: jsii.String("A"), AliasTarget: &awsroute53.CfnRecordSet_AliasTargetProperty{DnsName: alb.LoadBalancerDnsName(), HostedZoneId: alb.LoadBalancerCanonicalHostedZoneId(), EvaluateTargetHealth: jsii.Bool(false)}})
	file := os.Getenv("PDF_FRONTDOOR_CODE_FILE")
	if file == "" && os.Getenv("PDF_LOCALSTACK") != "1" {
		panic("set PDF_FRONTDOOR_CODE_FILE to private generated edge configuration")
	}
	if os.Getenv("PDF_LOCALSTACK") == "1" {
		file = "../build/local-frontdoor.js"
	}
	code, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	edgeDistribution(stack, token, jsii.String(requiredEdgeValue("PDF_EDGE_VIEWER_CERT_ARN", "arn:aws:acm:us-east-1:"+*stack.Account()+":certificate/")), jsii.String(requiredEdgeValue("PDF_EDGE_WEB_ACL_ARN", "arn:aws:wafv2:us-east-1:"+*stack.Account()+":global/webacl/agent-pdf-edge/")), jsii.String(string(code)))
	return token, cert
}

func backendListener(alb awselasticloadbalancingv2.ApplicationLoadBalancer, enabled bool, token *string, cert awscertificatemanager.Certificate) (awselasticloadbalancingv2.ApplicationListener, []awselasticloadbalancingv2.ListenerCondition) {
	props := &awselasticloadbalancingv2.BaseApplicationListenerProps{Port: jsii.Number(80), Open: jsii.Bool(false), DefaultAction: awselasticloadbalancingv2.ListenerAction_FixedResponse(jsii.Number(404), &awselasticloadbalancingv2.FixedResponseOptions{ContentType: jsii.String("application/json"), MessageBody: jsii.String(`{"error":"not_found"}`)})}
	conditions := []awselasticloadbalancingv2.ListenerCondition{awselasticloadbalancingv2.ListenerCondition_HostHeaders(&[]*string{alb.LoadBalancerDnsName()})}
	if enabled {
		props.Port = jsii.Number(originHTTPSPort())
		props.Certificates = &[]awselasticloadbalancingv2.IListenerCertificate{awselasticloadbalancingv2.ListenerCertificate_FromCertificateManager(cert)}
		props.SslPolicy = awselasticloadbalancingv2.SslPolicy_TLS13_RES
		conditions = []awselasticloadbalancingv2.ListenerCondition{awselasticloadbalancingv2.ListenerCondition_HostHeaders(&[]*string{jsii.String("origin." + domain)}), awselasticloadbalancingv2.ListenerCondition_HttpHeader(jsii.String("X-Agent-Pdf-Origin"), &[]*string{token})}
	}
	return alb.AddListener(jsii.String("Http"), props), conditions
}
