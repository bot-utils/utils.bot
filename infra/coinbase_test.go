package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/jsii-runtime-go"
)

func TestCoinbaseParametersStayScopedToThePrivateFunction(t *testing.T) {
	t.Setenv("PDF_DEPLOY_ACCOUNT_ID", "111111111111")
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			defer jsii.Close()
			app := awscdk.NewApp(nil)
			stack := awscdk.NewStack(app, jsii.String("CoinbaseScope"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("111111111111"), Region: jsii.String("us-east-2")}})
			fn := awslambda.NewFunction(stack, jsii.String("Payment"), &awslambda.FunctionProps{Runtime: awslambda.Runtime_NODEJS_22_X(), Handler: jsii.String("index.handler"), Code: awslambda.Code_FromInline(jsii.String("exports.handler=async()=>({pass:false});"))})
			coinbaseParameters(stack, fn, enabled)
			template := assertions.Template_FromStack(stack, nil)
			count := 0
			if enabled {
				count = 1
			}
			template.ResourceCountIs(jsii.String("AWS::IAM::Policy"), jsii.Number(float64(count)))
			resources := (*template.ToJSON())["Resources"].(map[string]interface{})
			for _, raw := range resources {
				r := raw.(map[string]interface{})
				if r["Type"] != "AWS::IAM::Policy" {
					continue
				}
				props := r["Properties"].(map[string]interface{})
				rawPolicy, _ := json.Marshal(props["PolicyDocument"])
				if strings.Contains(string(rawPolicy), "coinbaseProjectId") || strings.Contains(string(rawPolicy), "GetParametersByPath") || strings.Contains(string(rawPolicy), "kms:") {
					t.Fatal("unnecessary parameter/key capabilities")
				}
				statement := props["PolicyDocument"].(map[string]interface{})["Statement"].([]interface{})[0].(map[string]interface{})
				if statement["Action"] != "ssm:GetParameters" {
					t.Fatal("broadened SSM actions")
				}
				arns := statement["Resource"].([]interface{})
				if len(arns) != 3 {
					t.Fatal("broadened SSM resources")
				}
				for i, name := range []string{"coinbaseAPIKey", "coinbaseAPISecret", "receiveAddress"} {
					if arns[i] != "arn:aws:ssm:us-east-1:111111111111:parameter/pdf/"+name {
						t.Fatal("wrong region/account/resource scope")
					}
				}
				roles := props["Roles"].([]interface{})
				if len(roles) != 1 || !strings.Contains(string(mustJSON(roles)), "PaymentServiceRole") {
					t.Fatal("credential access not confined to payment role")
				}
			}
		})
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
