package csvcloud

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"pdfservice/internal/awsenv"
)

// Explicit no-compute probe of the actual customer capability: UploadPart.
// A successful late part is not proof of cleanup; re-abort/ListParts and a
// rejected completion are required. No task, payment or public route is used.
func TestPrivateAWSHeldPartAbort(t *testing.T) {
	run := os.Getenv("CSV_PRIVATE_S3_FENCE_RUN")
	if os.Getenv("CSV_PRIVATE_AWS_STAGE") != "s3-fence" || run == "" {
		t.Skip("explicit no-compute synthetic probe required")
	}
	if !opaque(run) || os.Getenv("CSV_PRIVATE_AWS_VALIDATE") != run {
		t.Fatal("invalid probe gate")
	}
	cfg, err := awsenv.Load()
	if err != nil {
		t.Fatal("credentials unavailable")
	}
	cfg.RetryMaxAttempts = 1
	a, err := clients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	bucket := "utils-csv-999999999999-" + run[:24]
	_, err = a.S3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket), CreateBucketConfiguration: &st.CreateBucketConfiguration{LocationConstraint: st.BucketLocationConstraintUsEast2}}, noS3Retry)
	if err != nil {
		t.Fatal("one-shot probe bucket creation failed; do not retry", err)
	}
	storage := Storage{Client: a.S3, Presigner: a.Parts, Bucket: bucket, Account: "999999999999", Gate: Gate{Enabled: true}}
	if (RunFence{Storage: storage, Control: a.S3, PolicyHash: AbsentBucketPolicyHash}).checkBucket(ctx) != nil {
		t.Fatal("probe bucket protections differ")
	}
	payload := []byte("synthetic held upload part\n")
	upload := Upload{Object: Object{JobID: run, ID: ID(), Slot: "file", Bytes: int64(len(payload)), SHA256: Hash(payload)}, Parts: []Part{{Number: 1, Bytes: int64(len(payload)), SHA256: Hash(payload)}}, Expires: time.Now().Add(time.Minute).Unix()}
	upload, err = storage.Begin(ctx, upload)
	if err != nil {
		t.Fatal("probe MPU creation unknown", err)
	}
	grant, err := storage.Grant(ctx, upload, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	ready := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	go func() {
		select {
		case <-release:
			_, _ = writer.Write(payload)
			_ = writer.Close()
		case <-ctx.Done():
			_ = writer.CloseWithError(ctx.Err())
		}
	}()
	req, err := http.NewRequestWithContext(ctx, "PUT", grant.URL, reader)
	if err != nil {
		t.Fatal("probe request")
	}
	req.Header = http.Header(grant.Headers).Clone()
	req.Header.Set("Expect", "100-continue")
	req.ContentLength = int64(len(payload))
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{Got100Continue: func() { close(ready) }}))
	type outcome struct {
		status int
		etag   string
	}
	done := make(chan outcome, 1)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{ExpectContinueTimeout: 2 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go func() {
		resp, e := client.Do(req)
		if e != nil {
			_ = reader.CloseWithError(e)
			done <- outcome{}
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		done <- outcome{resp.StatusCode, resp.Header.Get("ETag")}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("probe request was not accepted before abort")
	}
	observed, err := storage.AbortObservation(ctx, upload)
	if err != nil || !observed {
		t.Fatal("initial abort/ListParts did not confirm absence", err)
	}
	once.Do(func() { close(release) })
	var late outcome
	select {
	case late = <-done:
	case <-ctx.Done():
		t.Fatal("late part completion unknown")
	}
	t.Logf("PRIVATE_MULTIPART_LATE status=%d initial_abort_observed=true", late.status)
	if late.status != 200 && late.status != 404 {
		t.Fatal("unexpected held-part outcome")
	}
	observed, err = storage.AbortObservation(ctx, upload)
	if err != nil || !observed {
		t.Fatal("post-flight abort/ListParts did not confirm absence", err)
	}
	etag := late.etag
	if etag == "" {
		etag = `"synthetic-unavailable"`
	}
	_, err = a.S3.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String(bucket), Key: aws.String(upload.Object.key(false)), UploadId: aws.String(upload.ID), ExpectedBucketOwner: aws.String(storage.Account), MultipartUpload: &st.CompletedMultipartUpload{Parts: []st.CompletedPart{{PartNumber: aws.Int32(1), ETag: aws.String(etag), ChecksumSHA256: aws.String(checksum(Hash(payload)))}}}}, noS3Retry)
	if !apiCode(err, "NoSuchUpload") {
		t.Fatal("aborted upload could still complete", err)
	}
	objects, err := a.S3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(storage.Account)}, noS3Retry)
	if err != nil || len(objects.Contents) != 0 {
		t.Fatal("orphan object visible")
	}
	uploads, err := a.S3.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(storage.Account)}, noS3Retry)
	if err != nil || len(uploads.Uploads) != 0 {
		t.Fatal("orphan MPU visible")
	}
	_, err = a.S3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(storage.Account)}, noS3Retry)
	if err != nil {
		t.Fatal("probe bucket deletion", err)
	}
	replay, err := http.NewRequestWithContext(ctx, "PUT", grant.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	replay.Header = http.Header(grant.Headers).Clone()
	response, err := client.Do(replay)
	if err != nil {
		t.Fatal("replay absence unconfirmed")
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode != 404 || (!bytes.Contains(body, []byte("<Code>NoSuchBucket</Code>")) && !bytes.Contains(body, []byte("<Code>NoSuchUpload</Code>"))) {
		t.Fatal("revoked customer capability replay accepted", response.StatusCode)
	}
	t.Log("PRIVATE_MULTIPART_PROBE_VERIFIED repeated_abort=true no_parts=true completion_rejected=true no_objects=true replay_rejected=true")
}

// An HTTP success from an already accepted request does not establish that
// its object is readable after bucket deletion. Measure data access and fresh
// writes independently; ambiguous errors are never accepted as absence.
func TestPrivateAWSHeldPutAccessFence(t *testing.T) {
	run := os.Getenv("CSV_PRIVATE_S3_FENCE_RUN")
	if os.Getenv("CSV_PRIVATE_AWS_STAGE") != "s3-fence" || run == "" {
		t.Skip("explicit no-compute synthetic probe required")
	}
	if !opaque(run) || os.Getenv("CSV_PRIVATE_AWS_VALIDATE") != run {
		t.Fatal("invalid probe gate")
	}
	cfg, err := awsenv.Load()
	if err != nil {
		t.Fatal("credentials unavailable")
	}
	cfg.RetryMaxAttempts = 1
	a, err := clients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bucket := "utils-csv-999999999999-" + run[:24]
	_, err = a.S3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket), CreateBucketConfiguration: &st.CreateBucketConfiguration{LocationConstraint: st.BucketLocationConstraintUsEast2}}, noS3Retry)
	if err != nil {
		t.Fatal("one-shot probe bucket creation failed; do not retry", err)
	}
	storage := Storage{Client: a.S3, Presigner: a.Parts, Bucket: bucket, Account: "999999999999", Gate: Gate{Enabled: true}}
	if (RunFence{Storage: storage, Control: a.S3, PolicyHash: AbsentBucketPolicyHash}).checkBucket(ctx) != nil {
		t.Fatal("probe bucket protections differ")
	}
	late, err := beginPrivateLatePut(ctx, a, storage, run)
	if err != nil {
		t.Fatal("held PUT not established")
	}
	defer late.release()
	_, err = a.S3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(storage.Account)}, noS3Retry)
	if err != nil {
		t.Fatal("bucket deletion did not acknowledge", err)
	}
	late.release()
	var status int
	select {
	case status = <-late.done:
	case <-ctx.Done():
		t.Fatal("held PUT completion unknown")
	}
	if status != 200 && status != 404 {
		t.Fatal("held PUT status ambiguous", status)
	}
	t.Logf("PRIVATE_HELD_PUT_TERMINAL after_delete_ack=true status=%d", status)
	object, err := a.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(late.key), ExpectedBucketOwner: aws.String(storage.Account)}, noS3Retry)
	if object != nil && object.Body != nil {
		object.Body.Close()
	}
	if !apiCode(err, "NoSuchBucket") {
		t.Fatal("late object access was not rejected with NoSuchBucket", err)
	}
	_, err = a.S3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(late.key), Body: bytes.NewReader([]byte("synthetic replay\n")), ExpectedBucketOwner: aws.String(storage.Account), ServerSideEncryption: "AES256", IfNoneMatch: aws.String("*")}, noS3Retry)
	if !apiCode(err, "NoSuchBucket") {
		t.Fatal("new write not rejected with NoSuchBucket", err)
	}
	if late.replay() != 404 {
		t.Fatal("held capability replay not rejected")
	}
	if (BucketAbsence{Client: a.S3, Bucket: bucket, Account: storage.Account}).Verify(ctx) != nil {
		t.Fatal("bucket absence did not converge")
	}
	t.Log("PRIVATE_HELD_PUT_FENCE_VERIFIED object_read_rejected=true fresh_write_rejected=true replay_rejected=true converged_absence=true")
}
