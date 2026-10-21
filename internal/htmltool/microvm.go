package htmltool

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"pdfservice/internal/htmlrender"
	"pdfservice/internal/microvm"
)

type ThreatPresigner interface {
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

func BuildVMJob(ctx context.Context, reader SnapshotReader, signer ThreatPresigner, bucket string, input Input) (VMJob, error) {
	snapshot, err := LoadSnapshot(ctx, reader, bucket, time.Now())
	if err != nil {
		return VMJob{}, err
	}
	u, err := CanonicalURL(input.URL)
	if err != nil {
		return VMJob{}, err
	}
	if err = snapshot.Check(ctx, u.Hostname(), time.Now()); err != nil {
		return VMJob{}, err
	}
	manifest := snapshot.ManifestBytes()
	job := VMJob{Input: input, Manifest: manifest, Shards: make([]string, shardCount)}
	for i := range shardCount {
		key := shardKey(snapshot.Generation(), byte(i))
		out, e := signer.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}, func(o *s3.PresignOptions) { o.Expires = 2 * time.Minute })
		if e != nil || out == nil || out.Method != "GET" || !htmlrender.ThreatLink(out.URL, bucket, key) {
			return VMJob{}, ErrThreats
		}
		job.Shards[i] = out.URL
	}
	return job, nil
}

type VMRunner interface {
	Run(context.Context, []byte) ([]byte, error)
}

func MicroVMInvoker(runner VMRunner, reader SnapshotReader, signer ThreatPresigner, bucket string) WorkFunc {
	return func(ctx context.Context, input Input) (Result, error) {
		job, err := BuildVMJob(ctx, reader, signer, bucket, input)
		if err != nil {
			return Result{Error: Code(err)}, nil
		}
		payload, err := json.Marshal(job)
		if err != nil {
			return Result{}, microvm.ErrUnavailable
		}
		wire, err := runner.Run(ctx, payload)
		if err != nil {
			return Result{}, err
		}
		result, e := decodeResult(wire, input, true)
		if e != nil {
			return Result{}, microvm.ErrUnavailable
		}
		return result, nil
	}
}
