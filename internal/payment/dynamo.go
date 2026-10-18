package payment

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoStore struct {
	Client *dynamodb.Client
	Table  string
}

func (s DynamoStore) Get(ctx context.Context, key string) (*Binding, error) {
	out, err := s.Client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.Table), ConsistentRead: aws.Bool(true), Key: map[string]types.AttributeValue{"paymentKey": &types.AttributeValueMemberS{Value: key}}})
	if err != nil {
		return nil, err
	}
	if len(out.Item) == 0 {
		return nil, nil
	}
	str := func(k string) (string, error) {
		v, ok := out.Item[k].(*types.AttributeValueMemberS)
		if !ok {
			return "", fmt.Errorf("invalid binding field %s", k)
		}
		return v.Value, nil
	}
	num := func(k string) (int64, error) {
		v, ok := out.Item[k].(*types.AttributeValueMemberN)
		if !ok {
			return 0, fmt.Errorf("invalid binding field %s", k)
		}
		return strconv.ParseInt(v.Value, 10, 64)
	}
	b := &Binding{}
	b.PaymentKey = key
	for name, dst := range map[string]*string{"state": &b.State, "reservationID": &b.ReservationID} {
		if _, present := out.Item[name]; present {
			*dst, err = str(name)
			if err != nil {
				return nil, err
			}
		}
	}
	if _, present := out.Item["retryCount"]; present {
		b.RetryCount, err = num("retryCount")
		if err != nil {
			return nil, err
		}
	}
	for _, x := range []struct {
		k   string
		dst *string
	}{{"bodySHA256", &b.BodySHA256}, {"paymentProofSHA256", &b.PaymentProofSHA256}, {"transaction", &b.Transaction}} {
		*x.dst, err = str(x.k)
		if err != nil {
			return nil, err
		}
	}
	for _, x := range []struct {
		k   string
		dst *int64
	}{{"bodyLength", &b.BodyLength}, {"retryUntil", &b.RetryUntil}, {"expiresAt", &b.ExpiresAt}} {
		*x.dst, err = num(x.k)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}
func (s DynamoStore) Put(ctx context.Context, b Binding) error {
	item := map[string]types.AttributeValue{}
	for k, v := range map[string]string{"paymentKey": b.PaymentKey, "bodySHA256": b.BodySHA256, "paymentProofSHA256": b.PaymentProofSHA256, "transaction": b.Transaction} {
		item[k] = &types.AttributeValueMemberS{Value: v}
	}
	for k, v := range map[string]int64{"bodyLength": b.BodyLength, "retryUntil": b.RetryUntil, "expiresAt": b.ExpiresAt} {
		item[k] = &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
	}
	if b.State != "" {
		item["state"] = &types.AttributeValueMemberS{Value: b.State}
		item["reservationID"] = &types.AttributeValueMemberS{Value: b.ReservationID}
		item["retryCount"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(b.RetryCount, 10)}
	}
	_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.Table), Item: item, ConditionExpression: aws.String("attribute_not_exists(paymentKey)")})
	var conflict *types.ConditionalCheckFailedException
	if errors.As(err, &conflict) {
		return ErrConflict
	}
	return err
}

func (s DynamoStore) Complete(ctx context.Context, b Binding) error {
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.Table), Key: map[string]types.AttributeValue{"paymentKey": &types.AttributeValueMemberS{Value: b.PaymentKey}},
		UpdateExpression:         aws.String("SET #state = :paid, #txn = :txn, retryUntil = :until"),
		ConditionExpression:      aws.String("#state = :prepared AND reservationID = :id AND bodySHA256 = :body AND bodyLength = :length AND paymentProofSHA256 = :proof AND #txn = :empty"),
		ExpressionAttributeNames: map[string]string{"#state": "state", "#txn": "transaction"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":paid": &types.AttributeValueMemberS{Value: paidState}, ":prepared": &types.AttributeValueMemberS{Value: preparedState},
			":id": &types.AttributeValueMemberS{Value: b.ReservationID}, ":body": &types.AttributeValueMemberS{Value: b.BodySHA256},
			":length": &types.AttributeValueMemberN{Value: strconv.FormatInt(b.BodyLength, 10)}, ":proof": &types.AttributeValueMemberS{Value: b.PaymentProofSHA256},
			":empty": &types.AttributeValueMemberS{Value: ""}, ":txn": &types.AttributeValueMemberS{Value: b.Transaction},
			":until": &types.AttributeValueMemberN{Value: strconv.FormatInt(b.RetryUntil, 10)},
		},
	})
	return err
}

func (s DynamoStore) ClaimRetry(ctx context.Context, b Binding, now int64) error {
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.Table), Key: map[string]types.AttributeValue{"paymentKey": &types.AttributeValueMemberS{Value: b.PaymentKey}},
		UpdateExpression:         aws.String("SET retryCount = if_not_exists(retryCount, :zero) + :one"),
		ConditionExpression:      aws.String("paymentProofSHA256 = :proof AND bodySHA256 = :body AND bodyLength = :length AND #txn = :txn AND retryUntil > :now AND expiresAt > :now AND (attribute_not_exists(retryCount) OR retryCount < :max) AND (attribute_not_exists(#state) OR #state = :paid)"),
		ExpressionAttributeNames: map[string]string{"#state": "state", "#txn": "transaction"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":proof": &types.AttributeValueMemberS{Value: b.PaymentProofSHA256}, ":body": &types.AttributeValueMemberS{Value: b.BodySHA256},
			":length": &types.AttributeValueMemberN{Value: strconv.FormatInt(b.BodyLength, 10)}, ":txn": &types.AttributeValueMemberS{Value: b.Transaction},
			":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(now, 10)}, ":max": &types.AttributeValueMemberN{Value: strconv.FormatInt(MaxPaidRetries, 10)},
			":zero": &types.AttributeValueMemberN{Value: "0"}, ":one": &types.AttributeValueMemberN{Value: "1"}, ":paid": &types.AttributeValueMemberS{Value: paidState},
		},
	})
	var rejected *types.ConditionalCheckFailedException
	if errors.As(err, &rejected) {
		return ErrRetryLimit
	}
	return err
}
