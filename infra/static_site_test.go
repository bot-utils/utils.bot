package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudfrontorigins"
	"github.com/aws/jsii-runtime-go"
)

func TestStaticSiteIsPrivateOACNoDeploymentLambdaAndFewBehaviors(t *testing.T) {
	t.Setenv("PDF_DIRECT_API", "1")
	t.Setenv("PDF_STATIC_SITE", "1")
	t.Setenv("PDF_HOSTED_ZONE_ID", "ZEXAMPLE")
	code := filepath.Join(t.TempDir(), "function.js")
	if err := os.WriteFile(code, []byte("function handler(e){return e.request||e.response;}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PDF_SITE_REQUEST_CODE_FILE", code)
	t.Setenv("PDF_SITE_RESPONSE_CODE_FILE", code)
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("StaticSiteTest"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
	origin := awscloudfrontorigins.NewHttpOrigin(jsii.String("origin.utils.bot"), nil)
	staticSiteDistribution(stack, origin, jsii.String("arn:aws:acm:us-east-1:111111111111:certificate/test"), jsii.String("arn:aws:wafv2:us-east-1:111111111111:global/webacl/agent-pdf-edge/test"))
	template := assertions.Template_FromStack(stack, nil)
	for typ, count := range map[string]int{"AWS::S3::Bucket": 1, "AWS::S3::BucketPolicy": 1, "AWS::CloudFront::OriginAccessControl": 1, "AWS::CloudFront::Distribution": 1, "AWS::CloudFront::Function": 2, "AWS::Lambda::Function": 0, "AWS::CloudFront::OriginRequestPolicy": 0, "AWS::CloudFront::ResponseHeadersPolicy": 0, "AWS::CloudFront::CachePolicy": 0} {
		template.ResourceCountIs(jsii.String(typ), jsii.Number(float64(count)))
	}
	for _, raw := range (*template.ToJSON())["Resources"].(map[string]any) {
		r := raw.(map[string]any)
		p, _ := r["Properties"].(map[string]any)
		switch r["Type"] {
		case "AWS::S3::Bucket":
			if p["WebsiteConfiguration"] != nil || p["LoggingConfiguration"] != nil || p["AccessControl"] != nil || r["DeletionPolicy"] != "Retain" {
				t.Fatal("unsafe bucket", p)
			}
			for key, v := range p["PublicAccessBlockConfiguration"].(map[string]any) {
				if v != true {
					t.Fatal("public access allowed", key)
				}
			}
		case "AWS::CloudFront::Distribution":
			c := p["DistributionConfig"].(map[string]any)
			if c["WebACLId"] == nil || c["Logging"] != nil || len(c["CacheBehaviors"].([]any)) != 1 || c["Restrictions"] == nil {
				t.Fatal("perimeter or free-tier feature footprint drift", c)
			}
			def := c["DefaultCacheBehavior"].(map[string]any)
			if def["OriginRequestPolicyId"] != nil || def["ResponseHeadersPolicyId"] != nil || len(def["FunctionAssociations"].([]any)) != 2 {
				t.Fatal("custom policies or viewer admission absent", def)
			}
			origins := c["Origins"].([]any)
			if len(origins) != 2 {
				t.Fatal("unexpected origins")
			}
			found := false
			for _, raw := range origins {
				o := raw.(map[string]any)
				if o["S3OriginConfig"] != nil {
					found = o["OriginAccessControlId"] != nil
				}
			}
			if !found {
				t.Fatal("S3 can be reached without OAC")
			}
		case "AWS::S3::BucketPolicy":
			b, _ := json.Marshal(p)
			text := string(b)
			for _, required := range []string{"cloudfront.amazonaws.com", "AWS:SourceArn", "public/*", "aws:SecureTransport"} {
				if !strings.Contains(text, required) {
					t.Fatal("missing private bucket constraint", required, text)
				}
			}
		}
	}
}
func TestStaticWebsiteCannotSilentlyReplacePaymentIngress(t *testing.T) {
	t.Setenv("PDF_STATIC_SITE", "1")
	t.Setenv("PDF_DIRECT_API", "0")
	defer func() {
		if recover() == nil {
			t.Fatal("static site accepted without regional API")
		}
	}()
	staticSiteEnabled()
}

func TestStaticBucketNameDoesNotDiscloseAccountInOriginErrors(t *testing.T) {
	name := staticSiteBucketName("111111111111", "us-east-2")
	if strings.Contains(name, "111111111111") || name != staticSiteBucketName("111111111111", "us-east-2") || name == staticSiteBucketName("222222222222", "us-east-2") {
		t.Fatal("non-opaque, unstable or colliding site bucket name", name)
	}
}
