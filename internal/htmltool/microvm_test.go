package htmltool

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"pdfservice/internal/jsonwire"
	"pdfservice/internal/microvm"
)

type threatSigner struct{ calls int }

func (s *threatSigner) PresignGetObject(_ context.Context, in *s3.GetObjectInput, options ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	o := s3.PresignOptions{}
	for _, f := range options {
		f(&o)
	}
	if o.Expires != 2*time.Minute {
		panic("unbounded read capability")
	}
	s.calls++
	return &v4.PresignedHTTPRequest{Method: "GET", URL: "https://" + aws.ToString(in.Bucket) + ".s3.us-east-2.amazonaws.com/" + aws.ToString(in.Key) + "?X-Amz-Signature=test"}, nil
}

type vmRunnerFunc func(context.Context, []byte) ([]byte, error)

func (f vmRunnerFunc) Run(ctx context.Context, p []byte) ([]byte, error) { return f(ctx, p) }
func TestMicroVMBuildsOnlyPublicThreatCapabilitiesAndValidatesReturnedData(t *testing.T) {
	store := &objectStore{}
	now := time.Now()
	ctx := context.Background()
	if SaveSnapshot(ctx, store, "threat-fixture", dataFor(t, now, "evil.example"), now) != nil {
		t.Fatal("fixture")
	}
	signer := &threatSigner{}
	jobs := 0
	runner := vmRunnerFunc(func(_ context.Context, b []byte) ([]byte, error) {
		jobs++
		var job VMJob
		if jsonwire.Decode(b, &job, microvm.MaxJob) != nil || job.Input.URL != "https://example.com/private-canary" || len(job.Shards) != 256 {
			t.Fatal("worker request")
		}
		if strings.Contains(string(b), "payment") || strings.Contains(string(b), "AWS_SECRET_ACCESS_KEY") {
			t.Fatal("worker secret exposure")
		}
		for _, link := range job.Shards {
			if strings.Contains(link, "private-canary") {
				t.Fatal("customer data in public threat key")
			}
		}
		return json.Marshal(Result{URL: job.Input.URL, FinalURL: job.Input.URL, SourceStatus: 200, JavaScript: true, Markdown: "<script>malicious worker</script>"})
	})
	work := MicroVMInvoker(runner, store, signer, "threat-fixture")
	if _, e := work(ctx, Input{URL: "https://example.com/private-canary"}); e == nil || jobs != 1 || signer.calls != 256 {
		t.Fatal("hostile VM response not rejected")
	}
	out, e := work(ctx, Input{URL: "https://evil.example/"})
	if e != nil || out.Error != ErrBlocked.Error() || jobs != 1 {
		t.Fatal("known malicious domain reached worker")
	}
	for _, key := range store.reads {
		if strings.Contains(key, "private-canary") || strings.Contains(key, "example.com") {
			t.Fatal("customer data sent to S3")
		}
	}
}
