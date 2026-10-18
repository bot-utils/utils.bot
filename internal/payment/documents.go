package payment

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Bump when the native parser stack or its resource policy changes, so a failure
// under an old policy cannot deny a document under an improved one.
const DocumentPolicy = "pdfium-poppler-10s-100MiB-v1"
const DocumentFailureLifetime = 240 * time.Hour

type DocumentStore interface {
	Failed(context.Context, string, int64) (bool, error)
	MarkFailed(context.Context, string, int64) error
}

func documentKey(hash string) string {
	return "document:" + DocumentPolicy + ":" + strings.ToLower(hash)
}

func (s DynamoStore) Failed(ctx context.Context, hash string, now int64) (bool, error) {
	if !hexBytes(hash, 32, false) {
		return false, errors.New("invalid document hash")
	}
	out, err := s.Client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.Table), ConsistentRead: aws.Bool(true), Key: map[string]types.AttributeValue{"paymentKey": &types.AttributeValueMemberS{Value: documentKey(hash)}}})
	if err != nil {
		return false, err
	}
	if len(out.Item) == 0 {
		return false, nil
	}
	kind, ok := out.Item["kind"].(*types.AttributeValueMemberS)
	if !ok || kind.Value != "document_failure" {
		return false, errors.New("invalid document failure record")
	}
	expires, ok := out.Item["expiresAt"].(*types.AttributeValueMemberN)
	if !ok {
		return false, errors.New("invalid document failure expiry")
	}
	until, err := strconv.ParseInt(expires.Value, 10, 64)
	if err != nil || until <= 0 {
		return false, errors.New("invalid document failure expiry")
	}
	return now < until, nil // TTL deletion is asynchronous; never trust row presence alone.
}

func (s DynamoStore) MarkFailed(ctx context.Context, hash string, now int64) error {
	if !hexBytes(hash, 32, false) {
		return errors.New("invalid document hash")
	}
	_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.Table), Item: map[string]types.AttributeValue{
		"paymentKey": &types.AttributeValueMemberS{Value: documentKey(hash)},
		"kind":       &types.AttributeValueMemberS{Value: "document_failure"},
		"expiresAt":  &types.AttributeValueMemberN{Value: strconv.FormatInt(now+int64(DocumentFailureLifetime/time.Second), 10)},
	}, ConditionExpression: aws.String("attribute_not_exists(paymentKey) OR expiresAt <= :now"), ExpressionAttributeValues: map[string]types.AttributeValue{":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(now, 10)}}})
	var conflict *types.ConditionalCheckFailedException
	if errors.As(err, &conflict) {
		return nil
	} // Concurrent failure already recorded; no TTL extension.
	return err
}
