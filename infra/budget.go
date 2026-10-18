package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsbudgets"
	"github.com/aws/jsii-runtime-go"
)

// Account-wide Fargate usage includes future regions, architectures, Spot and
// storage charges. It does not depend on activated cost-allocation tags.
func fargateBudget(stack awscdk.Stack) {
	notifications := make([]interface{}, 0, 2)
	for _, dollars := range []float64{25, 50} {
		notifications = append(notifications, &awsbudgets.CfnBudget_NotificationWithSubscribersProperty{
			Notification: &awsbudgets.CfnBudget_NotificationProperty{
				NotificationType: jsii.String("ACTUAL"), ComparisonOperator: jsii.String("GREATER_THAN"),
				ThresholdType: jsii.String("ABSOLUTE_VALUE"), Threshold: jsii.Number(dollars),
			},
			Subscribers: &[]interface{}{&awsbudgets.CfnBudget_SubscriberProperty{
				SubscriptionType: jsii.String("EMAIL"), Address: jsii.String(alertEmail()),
			}},
		})
	}
	budget := awsbudgets.NewCfnBudget(stack, jsii.String("FargateBudget"), &awsbudgets.CfnBudgetProps{
		Budget: &awsbudgets.CfnBudget_BudgetDataProperty{
			BudgetName: jsii.String("agent-pdf-fargate-monthly"), BudgetType: jsii.String("COST"), TimeUnit: jsii.String("MONTHLY"),
			BudgetLimit: &awsbudgets.CfnBudget_SpendProperty{Amount: jsii.Number(50), Unit: jsii.String("USD")},
			Metrics:     &[]*string{jsii.String("UnblendedCost")},
			FilterExpression: &awsbudgets.CfnBudget_ExpressionProperty{And: &[]interface{}{
				&awsbudgets.CfnBudget_ExpressionProperty{Dimensions: &awsbudgets.CfnBudget_ExpressionDimensionValuesProperty{
					Key: jsii.String("USAGE_TYPE"), Values: &[]*string{jsii.String("Fargate")}, MatchOptions: &[]*string{jsii.String("CONTAINS")},
				}},
				&awsbudgets.CfnBudget_ExpressionProperty{Not: &awsbudgets.CfnBudget_ExpressionProperty{Dimensions: &awsbudgets.CfnBudget_ExpressionDimensionValuesProperty{
					Key: jsii.String("RECORD_TYPE"), Values: &[]*string{jsii.String("Credit"), jsii.String("Refund")},
				}}},
			}},
		},
		NotificationsWithSubscribers: &notifications,
	})
	awscdk.NewCfnOutput(stack, jsii.String("FargateBudgetName"), &awscdk.CfnOutputProps{Value: budget.Ref()})
}
