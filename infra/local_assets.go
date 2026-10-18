package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	"github.com/aws/jsii-runtime-go"
)

func localAssets(app awscdk.App) {
	stack := awscdk.NewStack(app, jsii.String("AgentPdfLocalAssets"), &awscdk.StackProps{Env: &awscdk.Environment{Account: jsii.String("000000000000"), Region: jsii.String("us-east-2")}})
	awss3.NewCfnBucket(stack, jsii.String("Assets"), &awss3.CfnBucketProps{BucketName: jsii.String("pdf-local-assets")})
}
