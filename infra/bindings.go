package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
	"github.com/aws/jsii-runtime-go"
)

func paymentBindings(stack awscdk.Stack) awsdynamodb.Table {
	// These on-demand targets can throttle excess work, but AWS does not
	// guarantee a strict request ceiling or a dollar spending cap.
	return awsdynamodb.NewTable(stack, jsii.String("PaymentBindings"), &awsdynamodb.TableProps{
		TableName:           jsii.String("agent-pdf-mock-payments"),
		PartitionKey:        &awsdynamodb.Attribute{Name: jsii.String("paymentKey"), Type: awsdynamodb.AttributeType_STRING},
		BillingMode:         awsdynamodb.BillingMode_PAY_PER_REQUEST,
		MaxReadRequestUnits: jsii.Number(50), MaxWriteRequestUnits: jsii.Number(25),
		TimeToLiveAttribute: jsii.String("expiresAt"), RemovalPolicy: awscdk.RemovalPolicy_RETAIN,
		DeletionProtection: jsii.Bool(true),
		Encryption:         awsdynamodb.TableEncryption_DEFAULT,
	})
}
