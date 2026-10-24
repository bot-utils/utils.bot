package csvcloud

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"pdfservice/internal/awsenv"
)

// AWSClients constructs regional SDK clients using the existing no-proxy,
// no-redirect credential/transport policy. Construction makes no service call.
// No external endpoint override or SDK logging is accepted for these adapters.
type AWSClients struct {
	S3     *s3.Client
	Parts  *s3.PresignClient
	Dynamo *dynamodb.Client
	ECS    *ecs.Client
	SQS    *sqs.Client
}

func LoadAWS() (AWSClients, error) {
	cfg, e := awsenv.Load()
	if e != nil {
		return AWSClients{}, ErrInvalid
	}
	return clients(cfg)
}
func clients(cfg aws.Config) (AWSClients, error) {
	if cfg.Region != Region || cfg.BaseEndpoint != nil || cfg.Credentials == nil || cfg.HTTPClient == nil {
		return AWSClients{}, ErrInvalid
	}
	cfg.RetryMaxAttempts = 1
	cfg.ClientLogMode = 0
	a := AWSClients{S3: s3.NewFromConfig(cfg), Dynamo: dynamodb.NewFromConfig(cfg), ECS: ecs.NewFromConfig(cfg), SQS: sqs.NewFromConfig(cfg)}
	a.Parts = s3.NewPresignClient(a.S3)
	return a, nil
}
