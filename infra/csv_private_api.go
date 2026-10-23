package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type csvPrivateRun struct {
	ID      string          `json:"id"`
	Until   int64           `json:"until"`
	Request json.RawMessage `json:"request"`
	Parts   json.RawMessage `json:"parts,omitempty"`
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

// The shared API identity pins exact pre-created runs and excludes input reads,
// result writes, dispatch, IAM, payment, SSM/TLS and queue access. The separate
// expiring boundary is combined below for the API and upload coordinator.
func csvPrivateStatements(account string, c csvPrivateConfig, _ bool) []awsiam.PolicyStatement {
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
	bindCSVUploadCoordinators(account, *config, awscdk.Stack_Of(task))
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
		if namespace {
			statements = nil
			for _, statement := range csvBoundaryStatements(account, *config) {
				statements = append(statements, statement.ToStatementJson())
			}
		}
		documents[name] = map[string]interface{}{"Version": "2012-10-17", "Statement": statements}
	}
	// Resolve ordinary-stack logical IDs without synthesizing a policy file.
	app := awscdk.NewApp(&awscdk.AppProps{AutoSynth: jsii.Bool(false)})
	stack := awscdk.NewStack(app, jsii.String("AgentPdfMock"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String(account), Region: jsii.String("us-east-2")}})
	roles := bindCSVUploadCoordinators(account, *config, stack)
	exports := map[string]interface{}{}
	for _, run := range config.Runs {
		role := roles[run.ID]
		resource := role.Node().DefaultChild().(awscdk.CfnElement)
		policy := role.Node().TryFindChild(jsii.String("DefaultPolicy"))
		policyResource := policy.Node().DefaultChild().(awscdk.CfnElement)
		statements := []interface{}{}
		for _, s := range csvUploadStatements(account, run, false) {
			statements = append(statements, s.ToStatementJson())
		}
		exports[run.ID] = map[string]interface{}{"role_id": stack.GetLogicalId(resource), "policy_id": stack.GetLogicalId(policyResource), "role_name": "AgentPdfMock-CsvUpload-" + run.ID[:16], "identity": map[string]interface{}{"Version": "2012-10-17", "Statement": statements}, "trust": map[string]interface{}{"Version": "2012-10-17", "Statement": []interface{}{map[string]interface{}{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]string{"AWS": "arn:aws:iam::" + account + ":role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_LocalCLIAccess_452e4a519811dc0f"}, "Condition": map[string]interface{}{"StringEquals": map[string]string{"sts:RoleSessionName": "csv-upload-" + run.ID[:16]}, "DateLessThan": map[string]string{"aws:CurrentTime": time.Unix(run.Until, 0).UTC().Format(time.RFC3339)}}}}}}
	}
	documents["upload_coordinators"] = exports
	raw, err := marshalPrivateCSVPolicies(stack, documents)
	if err != nil {
		panic("private CSV policy export failed")
	}
	if _, err := os.Stdout.Write(append(raw, '\n')); err != nil {
		panic("private CSV policy export write failed")
	}
	return true
}

// Resolve CDK/JSII map wrappers before encoding standalone IAM JSON. Direct
// encoding of ToStatementJson can leak transport markers into Conditions.
func marshalPrivateCSVPolicies(stack awscdk.Stack, documents interface{}) ([]byte, error) {
	raw, err := json.Marshal(stack.Resolve(documents))
	if err != nil {
		return nil, err
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	normalized, err := normalizePrivateCSVJSON(decoded)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

// Only the exact closed JSII map transport shape is accepted. Unknown or mixed
// wrappers fail rather than silently changing a generated permission document.
func normalizePrivateCSVJSON(value interface{}) (interface{}, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		if wrapped, ok := v["$jsii.map"]; ok {
			if len(v) != 1 {
				return nil, fmt.Errorf("mixed JSII map wrapper")
			}
			object, ok := wrapped.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("nonobject JSII map wrapper")
			}
			return normalizePrivateCSVJSON(object)
		}
		out := make(map[string]interface{}, len(v))
		for k, child := range v {
			if strings.HasPrefix(k, "$jsii") {
				return nil, fmt.Errorf("unknown JSII wrapper")
			}
			normalized, err := normalizePrivateCSVJSON(child)
			if err != nil {
				return nil, err
			}
			out[k] = normalized
		}
		return out, nil
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, child := range v {
			normalized, err := normalizePrivateCSVJSON(child)
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	case string:
		if strings.Contains(v, "${Token[") {
			return nil, fmt.Errorf("unresolved policy token")
		}
	}
	return value, nil
}

// The private upload consumer has a distinct exact-run identity, never the API
// task role. It cannot dispatch compute, assume another role, write results or
// call payment services. The existing separately reviewed supervisor owns task
// lifecycle. Unique-bucket deletion is limited to failed never-started jobs.
func csvUploadStatements(account string, run csvPrivateRun, namespace bool) []awsiam.PolicyStatement {
	bucket := "arn:aws:s3:::utils-csv-" + account + "-" + run.ID[:24]
	table := "arn:aws:dynamodb:us-east-2:" + account + ":table/utils-bot-csv-private-" + run.ID[:16]
	suffix := run.ID[:16]
	inputPath, resultPath := "/inputs/"+run.ID+"/*", "/results/"+run.ID+"/*"
	queue := "arn:aws:sqs:us-east-2:" + account + ":utils-bot-csv-private-" + run.ID[:16]
	if namespace {
		bucket = "arn:aws:s3:::utils-csv-" + account + "-*"
		table = "arn:aws:dynamodb:us-east-2:" + account + ":table/utils-bot-csv-private-*"
		queue = "arn:aws:sqs:us-east-2:" + account + ":utils-bot-csv-private-*"
		inputPath, resultPath = "/inputs/*/*", "/results/*/*"
		suffix = "Ceiling"
	}
	deadline := time.Unix(run.Until, 0).UTC().Format(time.RFC3339)
	condition := func() map[string]interface{} {
		return map[string]interface{}{"DateLessThan": map[string]string{"aws:CurrentTime": deadline}}
	}
	statement := func(sid string, actions, resources []string, conditions map[string]interface{}) awsiam.PolicyStatement {
		return awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Sid: jsii.String(sid + suffix), Actions: jsii.Strings(actions...), Resources: jsii.Strings(resources...), Conditions: &conditions})
	}
	keys := []string{"JOB/" + run.ID, "API_COMPLETE/" + run.ID, "API_DELIVERY/" + run.ID, "API_RETIRE/" + run.ID, "API_UPLOAD/*", "BROKER/" + run.ID, "OUTBOX/" + run.ID, "FENCE/" + run.ID, "CAPACITY", "BUDGET", "IDEMPOTENCY/*", "NONCE/*"}
	if namespace {
		keys = []string{"JOB/*", "API_COMPLETE/*", "API_DELIVERY/*", "API_RETIRE/*", "API_UPLOAD/*", "BROKER/*", "OUTBOX/*", "FENCE/*", "CAPACITY", "BUDGET", "IDEMPOTENCY/*", "NONCE/*"}
	}
	read, write := condition(), condition()
	read["ForAllValues:StringLike"] = map[string]interface{}{"dynamodb:LeadingKeys": keys}
	write["ForAllValues:StringLike"] = map[string]interface{}{"dynamodb:LeadingKeys": keys}
	write["ForAnyValue:StringEquals"] = map[string]string{"dynamodb:EnclosingOperation": "TransactWriteItems"}
	return []awsiam.PolicyStatement{
		statement("CsvUploadInput", []string{"s3:GetObject", "s3:PutObject", "s3:ListMultipartUploadParts", "s3:AbortMultipartUpload"}, []string{bucket + inputPath}, condition()),
		statement("CsvUploadErase", []string{"s3:DeleteObject", "s3:AbortMultipartUpload"}, []string{bucket + inputPath, bucket + resultPath}, condition()),
		statement("CsvUploadBucket", []string{"s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:GetBucketPublicAccessBlock", "s3:GetBucketOwnershipControls", "s3:GetBucketAcl", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration", "s3:GetReplicationConfiguration", "s3:GetEncryptionConfiguration", "s3:GetBucketPolicy", "s3:DeleteBucket"}, []string{bucket}, condition()),
		statement("CsvUploadRead", []string{"dynamodb:GetItem"}, []string{table}, read),
		statement("CsvUploadTransaction", []string{"dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"}, []string{table}, write),
		statement("CsvUploadQueue", []string{"sqs:SendMessage"}, []string{queue}, condition()),
	}
}
func bindCSVUploadCoordinators(account string, c csvPrivateConfig, scope constructs.Construct) map[string]awsiam.Role {
	out := map[string]awsiam.Role{}
	for _, run := range c.Runs {
		// This is the existing operator's exact IAM role, not the account root, API
		// role, service principal or a wildcard PrincipalArn condition.
		trust := awsiam.NewPrincipalWithConditions(awsiam.NewArnPrincipal(jsii.String("arn:aws:iam::"+account+":role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_LocalCLIAccess_452e4a519811dc0f")), &map[string]interface{}{"StringEquals": map[string]string{"sts:RoleSessionName": "csv-upload-" + run.ID[:16]}, "DateLessThan": map[string]string{"aws:CurrentTime": time.Unix(run.Until, 0).UTC().Format(time.RFC3339)}})
		role := awsiam.NewRole(scope, jsii.String("CsvUpload"+run.ID[:16]), &awsiam.RoleProps{RoleName: jsii.String("AgentPdfMock-CsvUpload-" + run.ID[:16]), AssumedBy: trust, MaxSessionDuration: awscdk.Duration_Hours(jsii.Number(1)), PermissionsBoundary: awsiam.ManagedPolicy_FromManagedPolicyArn(scope, jsii.String("CsvUploadBoundary"+run.ID[:16]), jsii.String(namedPolicyArn(account, runtimeBoundaryName)))})
		for _, s := range csvUploadStatements(account, run, false) {
			role.AddToPolicy(s)
		}
		out[run.ID] = role
	}
	return out
}

// A managed-policy boundary is limited to 6 KiB. The expiring namespace ceiling
// is combined across roles; each identity policy still pins one exact run.
func csvBoundaryStatements(account string, c csvPrivateConfig) []awsiam.PolicyStatement {
	last := c.Runs[0]
	for _, run := range c.Runs {
		if run.Until > last.Until {
			last = run
		}
	}
	statements := csvUploadStatements(account, last, true)
	conditions := map[string]interface{}{"DateLessThan": map[string]string{"aws:CurrentTime": time.Unix(last.Until, 0).UTC().Format(time.RFC3339)}}
	statements = append(statements, awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{Sid: jsii.String("PrivateCsvResultReadCeiling"), Actions: jsii.Strings("s3:GetObject"), Resources: jsii.Strings("arn:aws:s3:::utils-csv-" + account + "-*/results/*/*"), Conditions: &conditions}))
	return statements
}
