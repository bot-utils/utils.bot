package payment

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func (s DynamoStore) GetFailureQuota(ctx context.Context, key string, now int64) (FailureQuota, error) {
	quota, _, err := s.getFailureQuotaRecord(ctx, key, now)
	return quota, err
}

func (s DynamoStore) getFailureQuotaRecord(ctx context.Context, key string, now int64) (FailureQuota, map[string]struct{}, error) {
	var quota FailureQuota
	out, err := s.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.Table), ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{"paymentKey": &types.AttributeValueMemberS{Value: key}},
	})
	if err != nil {
		return quota, nil, err
	}
	if len(out.Item) == 0 {
		return quota, nil, nil
	}
	kind, ok := out.Item["kind"].(*types.AttributeValueMemberS)
	if !ok || kind.Value != failedParseQuotaKind {
		return quota, nil, errors.New("invalid failure quota kind")
	}
	parseCount := func(name string) (int64, error) {
		value, present := out.Item[name]
		if !present {
			return 0, nil
		}
		number, ok := value.(*types.AttributeValueMemberN)
		if !ok {
			return 0, errors.New("invalid failure quota count")
		}
		count, err := strconv.ParseInt(number.Value, 10, 64)
		if err != nil || count <= 0 {
			return 0, errors.New("invalid failure quota count")
		}
		return count, nil
	}
	quota.Unpaid, err = parseCount("failureCount")
	if err != nil {
		return quota, nil, err
	}
	quota.Abandonments, err = parseCount("abandonmentCount")
	if err != nil || quota.Unpaid+quota.Abandonments <= 0 {
		return quota, nil, errors.New("invalid failure quota count")
	}
	expiryValue, ok := out.Item["expiresAt"].(*types.AttributeValueMemberN)
	if !ok {
		return quota, nil, errors.New("invalid failure quota expiry")
	}
	quota.ExpiresAt, err = strconv.ParseInt(expiryValue.Value, 10, 64)
	if err != nil || quota.ExpiresAt <= 0 {
		return quota, nil, errors.New("invalid failure quota expiry")
	}
	events := map[string]struct{}{}
	set, ok := out.Item["failureEvents"].(*types.AttributeValueMemberSS)
	if !ok || len(set.Value) == 0 || int64(len(set.Value)) > maxFailedParseEvents {
		return quota, nil, errors.New("invalid failure quota events")
	}
	for _, eventID := range set.Value {
		if !hexBytes(eventID, 32, false) {
			return quota, nil, errors.New("invalid failure quota event")
		}
		events[eventID] = struct{}{}
	}
	if int64(len(events)) != quota.Unpaid+quota.Abandonments {
		return quota, nil, errors.New("inconsistent failure quota count")
	}
	if quota.ExpiresAt <= now {
		return FailureQuota{}, nil, nil
	}
	return quota, events, nil
}

func (s DynamoStore) IncrementFailureQuota(ctx context.Context, key string, expiresAt int64, eventID, eventType string) error {
	countName := "failureCount"
	if eventType == quotaEventAbandoned {
		countName = "abandonmentCount"
	} else if eventType != quotaEventUnpaid {
		return fmt.Errorf("invalid failure quota event type")
	}
	if !strings.HasPrefix(key, failedParseQuotaNamespace) || !hexBytes(strings.TrimPrefix(key, failedParseQuotaNamespace), 32, false) || expiresAt <= 0 || !hexBytes(eventID, 32, false) {
		return fmt.Errorf("invalid failure quota update")
	}
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.Table),
		Key:                 map[string]types.AttributeValue{"paymentKey": &types.AttributeValueMemberS{Value: key}},
		UpdateExpression:    aws.String("SET #kind = if_not_exists(#kind, :kind), expiresAt = if_not_exists(expiresAt, :expires) ADD #count :one, #events :events"),
		ConditionExpression: aws.String("attribute_not_exists(paymentKey) OR (#kind = :kind AND expiresAt = :expires AND attribute_exists(#events) AND size(#events) < :eventCap AND NOT contains(#events, :event))"),
		ExpressionAttributeNames: map[string]string{
			"#kind": "kind", "#count": countName, "#events": "failureEvents",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":kind":     &types.AttributeValueMemberS{Value: failedParseQuotaKind},
			":expires":  &types.AttributeValueMemberN{Value: strconv.FormatInt(expiresAt, 10)},
			":one":      &types.AttributeValueMemberN{Value: "1"},
			":events":   &types.AttributeValueMemberSS{Value: []string{eventID}},
			":event":    &types.AttributeValueMemberS{Value: eventID},
			":eventCap": &types.AttributeValueMemberN{Value: strconv.FormatInt(maxFailedParseEvents, 10)},
		},
	})
	if err == nil {
		return nil
	}
	// UpdateItem is not intrinsically idempotent after a lost HTTP response.
	// Reconcile any error with a strong read: if this exact hashed event was
	// committed, treat the call (or a replayed Lambda event) as successful.
	quota, events, readErr := s.getFailureQuotaRecord(ctx, key, expiresAt-1)
	if readErr == nil && quota.ExpiresAt == expiresAt {
		if _, committed := events[eventID]; committed {
			return nil
		}
	}
	return err
}
