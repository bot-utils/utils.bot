package main

import (
	"testing"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/assertions"
	"github.com/aws/jsii-runtime-go"
)

func TestFargateBudgetTemplate(t *testing.T) {
	t.Setenv("PDF_ALERT_EMAIL", "ops@example.test")
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stack := awscdk.NewStack(app, jsii.String("BudgetTest"), nil)
	fargateBudget(stack)
	template := assertions.Template_FromStack(stack, nil)
	template.ResourceCountIs(jsii.String("AWS::Budgets::Budget"), jsii.Number(1))
	template.ResourceCountIs(jsii.String("AWS::Budgets::BudgetsAction"), jsii.Number(0))
	template.ResourceCountIs(jsii.String("AWS::SNS::Topic"), jsii.Number(0))
	template.HasResourceProperties(jsii.String("AWS::Budgets::Budget"), map[string]interface{}{
		"Budget": map[string]interface{}{
			"BudgetName": "agent-pdf-fargate-monthly", "BudgetType": "COST", "TimeUnit": "MONTHLY",
			"BudgetLimit": map[string]interface{}{"Amount": 50, "Unit": "USD"},
			"Metrics":     []interface{}{"UnblendedCost"},
			"FilterExpression": map[string]interface{}{"And": []interface{}{
				map[string]interface{}{"Dimensions": map[string]interface{}{"Key": "USAGE_TYPE", "Values": []interface{}{"Fargate"}, "MatchOptions": []interface{}{"CONTAINS"}}},
				map[string]interface{}{"Not": map[string]interface{}{"Dimensions": map[string]interface{}{"Key": "RECORD_TYPE", "Values": []interface{}{"Credit", "Refund"}}}},
			}},
		},
		"NotificationsWithSubscribers": []interface{}{
			budgetNotification(25), budgetNotification(50),
		},
	})
}

func budgetNotification(threshold int) interface{} {
	return map[string]interface{}{
		"Notification": map[string]interface{}{"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN", "ThresholdType": "ABSOLUTE_VALUE", "Threshold": threshold},
		"Subscribers":  []interface{}{map[string]interface{}{"SubscriptionType": "EMAIL", "Address": "ops@example.test"}},
	}
}
