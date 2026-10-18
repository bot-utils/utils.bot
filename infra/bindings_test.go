package main

import (
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
)

func TestPaymentTableKeepsTTLAndOnDemandTargets(t *testing.T) {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("BindingTest"), nil)
	paymentBindings(stack)
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::DynamoDB::Table"), jsii.Number(1))
	template.HasResourceProperties(jsii.String("AWS::DynamoDB::Table"), map[string]any{
		"TableName": "agent-pdf-mock-payments", "BillingMode": "PAY_PER_REQUEST",
		"DeletionProtectionEnabled": true,
		"OnDemandThroughput":        map[string]any{"MaxReadRequestUnits": 50, "MaxWriteRequestUnits": 25},
		"TimeToLiveSpecification":   map[string]any{"AttributeName": "expiresAt", "Enabled": true},
		"KeySchema":                 []any{map[string]any{"AttributeName": "paymentKey", "KeyType": "HASH"}},
	})
	template.HasResource(jsii.String("AWS::DynamoDB::Table"), map[string]any{
		"DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
	})
}
