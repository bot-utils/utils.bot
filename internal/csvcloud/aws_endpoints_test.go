package csvcloud

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestMetadataClientKeepsRegionalHostWithAccountCredentials(t *testing.T) {
	for _, account := range []string{"", "999999999999"} {
		t.Run(map[bool]string{true: "account_metadata", false: "no_account_metadata"}[account != ""], func(t *testing.T) {
			calls := 0
			cfg := sdkConfig(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "dynamodb.us-east-2.amazonaws.com" {
					t.Fatalf("metadata request escaped the fixed regional DNS allowlist: %s", r.URL.Host)
				}
				return response(200, `{}`, nil), nil
			})
			cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "synthetic", SessionToken: "synthetic", AccountID: account}, nil
			})
			clients, err := clients(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = clients.Dynamo.GetItem(context.Background(), &dynamodb.GetItemInput{TableName: aws.String("utils-bot-csv-private-synthetic"), Key: map[string]d.AttributeValue{"pk": &d.AttributeValueMemberS{Value: "JOB/synthetic"}}})
			if err != nil || calls != 1 {
				t.Fatal("metadata request failed or repeated", err, calls)
			}
		})
	}
}
