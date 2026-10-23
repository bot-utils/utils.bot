package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/jsii-runtime-go"
)

type csvPrivateRun struct {
	ID      string          `json:"id"`
	Until   int64           `json:"until"`
	Request json.RawMessage `json:"request"`
}
type csvPrivateConfig struct {
	Account       string          `json:"account"`
	SyntheticOnly bool            `json:"synthetic_only"`
	AllowedIP     string          `json:"allowed_ip"`
	KeySHA256     string          `json:"key_sha256"`
	ALBPeers      []string        `json:"alb_peers"`
	Runs          []csvPrivateRun `json:"runs"`
}

func csvPrivateSettings() (*csvPrivateConfig, string) {
	enabled, raw := os.Getenv("PDF_CSV_PRIVATE_ENABLED"), os.Getenv("PDF_CSV_PRIVATE_CONFIG")
	if enabled == "" || enabled == "0" {
		if raw != "" {
			panic("private CSV config requires explicit enable")
		}
		return nil, ""
	}
	if enabled != "1" || !directAPIEnabled() || len(raw) > 32<<10 {
		panic("private CSV requires explicit private mode and regional API")
	}
	var c csvPrivateConfig
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil {
		panic("invalid private CSV JSON")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		panic("trailing private CSV JSON")
	}
	if !accountPattern.MatchString(c.Account) || !c.SyntheticOnly || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.KeySHA256) || !ownerCIDR(c.AllowedIP+"/32") || len(c.Runs) < 1 || len(c.Runs) > 5 || len(c.ALBPeers) < 1 || len(c.ALBPeers) > 4 {
		panic("invalid private CSV deployment config")
	}
	for _, raw := range c.ALBPeers {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().IsPrivate() || !p.Addr().Is4() || p.Bits() < 24 || p != p.Masked() || p.String() != raw {
			panic("invalid private CSV ALB peer")
		}
	}
	seen := map[string]bool{}
	for _, run := range c.Runs {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(run.ID) || seen[run.ID] || run.Until <= time.Now().Unix() || run.Until > time.Now().Add(2*time.Hour).Unix() || !json.Valid(run.Request) {
			panic("invalid private CSV fixture")
		}
		seen[run.ID] = true
	}
	return &c, raw
}

// The temporary ceiling uses the private namespace; the identity policy pins
// exact pre-created runs. Both exclude input reads, result writes, dispatch,
// IAM, payment, SSM/TLS and queue access from the shared API.
func csvPrivateStatements(account string, c csvPrivateConfig, namespace bool) []awsiam.PolicyStatement {
	until := int64(0)
	inputs, results, tables := []*string{}, []*string{}, []*string{}
	for _, run := range c.Runs {
		if run.Until > until {
			until = run.Until
		}
		inputs = append(inputs, jsii.String("arn:aws:s3:::utils-csv-"+account+"-"+run.ID[:24]+"/inputs/"+run.ID+"/*"))
		results = append(results, jsii.String("arn:aws:s3:::utils-csv-"+account+"-"+run.ID[:24]+"/results/"+run.ID+"/*"))
		tables = append(tables, jsii.String("arn:aws:dynamodb:us-east-2:"+account+":table/utils-bot-csv-private-"+run.ID[:16]))
	}
	if namespace {
		inputs = []*string{jsii.String("arn:aws:s3:::utils-csv-" + account + "-*/inputs/*/*")}
		results = []*string{jsii.String("arn:aws:s3:::utils-csv-" + account + "-*/results/*/*")}
		tables = []*string{jsii.String("arn:aws:dynamodb:us-east-2:" + account + ":table/utils-bot-csv-private-*")}
	}
	deadline := time.Unix(until, 0).UTC().Format(time.RFC3339)
	conditions := func() map[string]interface{} {
		return map[string]interface{}{"DateLessThan": map[string]string{"aws:CurrentTime": deadline}}
	}
	keys := []string{"JOB/*", "API_UPLOAD/*", "API_DELIVERY/*", "API_COMPLETE/*", "CAPACITY", "IDEMPOTENCY/*", "NONCE/*"}
	getConditions := conditions()
	getConditions["ForAllValues:StringLike"] = map[string]interface{}{"dynamodb:LeadingKeys": keys}
	writeConditions := conditions()
	writeConditions["ForAllValues:StringLike"] = map[string]interface{}{"dynamodb:LeadingKeys": keys}
	writeConditions["ForAnyValue:StringEquals"] = map[string]string{"dynamodb:EnclosingOperation": "TransactWriteItems"}
	uploadConditions, resultConditions := conditions(), conditions()
	return []awsiam.PolicyStatement{
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Sid: jsii.String("PrivateCsvInputUpload"), Actions: jsii.Strings("s3:PutObject"), Resources: &inputs, Conditions: &uploadConditions}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Sid: jsii.String("PrivateCsvResultRead"), Actions: jsii.Strings("s3:GetObject"), Resources: &results, Conditions: &resultConditions}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Sid: jsii.String("PrivateCsvMetadataRead"), Actions: jsii.Strings("dynamodb:GetItem"), Resources: &tables, Conditions: &getConditions}),
		awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Sid: jsii.String("PrivateCsvMetadataTransaction"), Actions: jsii.Strings("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"), Resources: &tables, Conditions: &writeConditions}),
	}
}
func bindPrivateCSV(account string, task awsecs.FargateTaskDefinition, container awsecs.ContainerDefinition) {
	config, raw := csvPrivateSettings()
	if config == nil {
		return
	}
	if config.Account != account {
		panic("private CSV account differs from deployment")
	}
	for _, statement := range csvPrivateStatements(account, *config, false) {
		task.AddToTaskRolePolicy(statement)
	}
	container.AddEnvironment(jsii.String("CSV_PRIVATE_ENABLED"), jsii.String("1"))
	container.AddEnvironment(jsii.String("CSV_PRIVATE_CONFIG"), jsii.String(raw))
}

// The operator can obtain the exact reviewed policy documents on stdout without
// synthesizing a CloudFormation/policy file or making an AWS call.
func emitPrivateCSVPolicies() bool {
	if os.Getenv("CSV_PRIVATE_POLICY_ONLY") != "1" {
		return false
	}
	account := os.Getenv("CDK_DEFAULT_ACCOUNT")
	requireDeploymentAccount(account, false)
	config, _ := csvPrivateSettings()
	if config == nil || config.Account != account {
		panic("private CSV policy export requires exact account/config")
	}
	documents := map[string]interface{}{}
	for name, namespace := range map[string]bool{"identity": false, "boundary_additions": true} {
		statements := []interface{}{}
		for _, statement := range csvPrivateStatements(account, *config, namespace) {
			statements = append(statements, statement.ToStatementJson())
		}
		documents[name] = map[string]interface{}{"Version": "2012-10-17", "Statement": statements}
	}
	if json.NewEncoder(os.Stdout).Encode(documents) != nil {
		panic("private CSV policy export failed")
	}
	return true
}
