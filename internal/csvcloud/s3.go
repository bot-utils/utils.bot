package csvcloud

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type S3API interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	ListMultipartUploads(context.Context, *s3.ListMultipartUploadsInput, ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error)
	CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput, ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	ListParts(context.Context, *s3.ListPartsInput, ...func(*s3.Options)) (*s3.ListPartsOutput, error)
	CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput, ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput, ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}
type PartPresigner interface {
	PresignUploadPart(context.Context, *s3.UploadPartInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}
type Storage struct {
	Client          S3API
	Presigner       PartPresigner
	Bucket, Account string
	Gate            Gate
}
type Part struct {
	Number int32
	Bytes  int64
	SHA256 string
}
type Upload struct {
	Object  Object
	ID      string
	Parts   []Part
	Expires int64
}
type UploadGrant struct {
	URL     string
	Headers map[string][]string
	Bytes   int64
	Expires int64
}

func (UploadGrant) String() string   { return "CSV upload grant [redacted]" }
func (UploadGrant) GoString() string { return "CSV upload grant [redacted]" }
func noS3Retry(o *s3.Options)        { o.RetryMaxAttempts = 1 }
func checksum(v string) string {
	b, _ := hex.DecodeString(v)
	return base64.StdEncoding.EncodeToString(b)
}
func missing(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) && (api.ErrorCode() == "NoSuchKey" || api.ErrorCode() == "NotFound" || api.ErrorCode() == "NoSuchUpload")
}
func (u Upload) valid() bool {
	if !u.Object.valid() || u.Object.Slot == "result" || len(u.Parts) < 1 || len(u.Parts) > 128 {
		return false
	}
	var total int64
	for i, p := range u.Parts {
		if p.Number != int32(i+1) || p.Bytes <= 0 || p.Bytes > MaxInput || !opaque(p.SHA256) || i < len(u.Parts)-1 && p.Bytes < 5<<20 {
			return false
		}
		total += p.Bytes
	}
	return total == u.Object.Bytes
}

// Begin must follow the controller's durable CREATING reservation. An uncertain
// response is never retried here: reconcile the exact unique key before progress.
func (s Storage) Begin(ctx context.Context, u Upload) (Upload, error) {
	if !s.Gate.Enabled {
		return u, ErrDisabled
	}
	if !u.valid() || u.ID != "" {
		return u, ErrInvalid
	}
	out, err := s.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(s.Bucket), Key: aws.String(u.Object.key(false)), ExpectedBucketOwner: aws.String(s.Account), ServerSideEncryption: st.ServerSideEncryptionAes256, ChecksumAlgorithm: st.ChecksumAlgorithmSha256, ContentType: aws.String("application/octet-stream")}, noS3Retry)
	if err != nil || out.UploadId == nil || *out.UploadId == "" {
		return u, ErrUnknown
	}
	u.ID = *out.UploadId
	return u, nil
}
func (s Storage) Grant(ctx context.Context, u Upload, n int32, now time.Time) (UploadGrant, error) {
	var grant UploadGrant
	if !s.Gate.Enabled {
		return grant, ErrDisabled
	}
	if !u.valid() || u.ID == "" || n < 1 || int(n) > len(u.Parts) || now.Unix() >= u.Expires {
		return grant, ErrInvalid
	}
	p := u.Parts[n-1]
	until := min(u.Expires, now.Add(5*time.Minute).Unix())
	duration := time.Duration(until-now.Unix()) * time.Second
	out, err := s.Presigner.PresignUploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String(s.Bucket), Key: aws.String(u.Object.key(false)), ExpectedBucketOwner: aws.String(s.Account), UploadId: aws.String(u.ID), PartNumber: aws.Int32(n), ContentLength: aws.Int64(p.Bytes), ChecksumSHA256: aws.String(checksum(p.SHA256))}, func(o *s3.PresignOptions) { o.Expires = duration })
	if err != nil || out.SignedHeader.Get("Content-Length") == "" || out.SignedHeader.Get("X-Amz-Checksum-Sha256") != checksum(p.SHA256) {
		return grant, ErrIntegrity
	}
	return UploadGrant{URL: out.URL, Headers: out.SignedHeader, Bytes: p.Bytes, Expires: until}, nil
}
func (s Storage) Complete(ctx context.Context, u Upload) (Object, error) {
	ref := u.Object
	if !s.Gate.Enabled {
		return ref, ErrDisabled
	}
	if !u.valid() || u.ID == "" {
		return ref, ErrInvalid
	}
	listed, err := s.Client.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String(s.Bucket), Key: aws.String(ref.key(false)), UploadId: aws.String(u.ID), ExpectedBucketOwner: aws.String(s.Account), MaxParts: aws.Int32(129)}, noS3Retry)
	if err != nil {
		return ref, ErrUnknown
	}
	if aws.ToBool(listed.IsTruncated) || len(listed.Parts) != len(u.Parts) {
		return ref, ErrIntegrity
	}
	parts := make([]st.CompletedPart, 0, len(u.Parts))
	for i, p := range listed.Parts {
		want := u.Parts[i]
		if aws.ToInt32(p.PartNumber) != want.Number || aws.ToInt64(p.Size) != want.Bytes || aws.ToString(p.ChecksumSHA256) != checksum(want.SHA256) || p.ETag == nil {
			return ref, ErrIntegrity
		}
		parts = append(parts, st.CompletedPart{PartNumber: p.PartNumber, ETag: p.ETag, ChecksumSHA256: p.ChecksumSHA256})
	}
	out, err := s.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String(s.Bucket), Key: aws.String(ref.key(false)), UploadId: aws.String(u.ID), ExpectedBucketOwner: aws.String(s.Account), IfNoneMatch: aws.String("*"), MpuObjectSize: aws.Int64(ref.Bytes), MultipartUpload: &st.CompletedMultipartUpload{Parts: parts}}, noS3Retry)
	if err != nil || out.ETag == nil {
		return ref, ErrUnknown
	}
	ref.ETag = *out.ETag
	// SHA256 from S3 MPU is composite. Stream the actual completed object to verify
	// the client's full-file SHA256, independently of ETag/transport checksums.
	return s.VerifyInput(ctx, ref)
}
func (s Storage) VerifyInput(ctx context.Context, ref Object) (Object, error) {
	if !s.Gate.Enabled {
		return ref, ErrDisabled
	}
	if !ref.valid() || ref.Slot == "result" {
		return ref, ErrInvalid
	}
	head, err := s.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(ref.key(false)), ExpectedBucketOwner: aws.String(s.Account)}, noS3Retry)
	if err != nil {
		return ref, ErrUnknown
	}
	if head.ETag == nil || head.VersionId != nil || aws.ToInt64(head.ContentLength) != ref.Bytes || len(head.Metadata) != 0 || head.ServerSideEncryption != st.ServerSideEncryptionAes256 || ref.ETag != "" && ref.ETag != *head.ETag {
		return ref, ErrIntegrity
	}
	ref.ETag = *head.ETag
	body, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(ref.key(false)), ExpectedBucketOwner: aws.String(s.Account), IfMatch: aws.String(ref.ETag)}, noS3Retry)
	if err != nil {
		return ref, ErrUnknown
	}
	defer body.Body.Close()
	if aws.ToString(body.ETag) != ref.ETag || body.VersionId != nil || aws.ToInt64(body.ContentLength) != ref.Bytes || len(body.Metadata) != 0 || body.ServerSideEncryption != st.ServerSideEncryptionAes256 {
		return ref, ErrIntegrity
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(body.Body, ref.Bytes+1))
	if err != nil || n != ref.Bytes || hex.EncodeToString(h.Sum(nil)) != ref.SHA256 {
		return ref, ErrIntegrity
	}
	return ref, nil
}

// PutResult stores only a pre-bounded candidate; VerifyResult must succeed before
// the controller conditionally publishes its manifest or offers any payment.
func (s Storage) PutResult(ctx context.Context, m Manifest, data io.Reader) (Manifest, error) {
	stored, err := s.putCandidate(ctx, m, data)
	if err != nil {
		return stored, err
	}
	return s.VerifyResult(ctx, stored)
}

// putCandidate needs only write permission. It does not claim stored-result
// integrity; a separate controller must read and verify before publication.
func (s Storage) putCandidate(ctx context.Context, m Manifest, data io.Reader) (Manifest, error) {
	if !s.Gate.Enabled {
		return m, ErrDisabled
	}
	candidate := m
	candidate.Object.ETag = "candidate"
	if !candidate.Valid() {
		return m, ErrInvalid
	}
	out, err := s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(m.Object.key(true)), ExpectedBucketOwner: aws.String(s.Account), IfNoneMatch: aws.String("*"), ServerSideEncryption: st.ServerSideEncryptionAes256, ContentType: aws.String("application/gzip"), ContentLength: aws.Int64(m.Object.Bytes), ChecksumSHA256: aws.String(checksum(m.Object.SHA256)), Body: io.LimitReader(data, m.Object.Bytes+1)}, noS3Retry)
	if err != nil || out.ETag == nil {
		return m, ErrUnknown
	}
	m.Object.ETag = *out.ETag
	return m, nil
}

type countingHash struct {
	H hash.Hash
	N int64
}

func (w *countingHash) Write(p []byte) (int, error) {
	n, e := w.H.Write(p)
	w.N += int64(n)
	return n, e
}
func (s Storage) VerifyResult(ctx context.Context, m Manifest) (Manifest, error) {
	if !s.Gate.Enabled {
		return m, ErrDisabled
	}
	if !m.Valid() {
		return m, ErrInvalid
	}
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(m.Object.key(true)), ExpectedBucketOwner: aws.String(s.Account), IfMatch: aws.String(m.Object.ETag)}, noS3Retry)
	if err != nil {
		return m, ErrUnknown
	}
	defer out.Body.Close()
	if aws.ToString(out.ETag) != m.Object.ETag || out.VersionId != nil || len(out.Metadata) != 0 || out.ServerSideEncryption != st.ServerSideEncryptionAes256 || aws.ToInt64(out.ContentLength) != m.Object.Bytes {
		return m, ErrIntegrity
	}
	encoded := &countingHash{H: sha256.New()}
	z, err := gzip.NewReader(io.TeeReader(io.LimitReader(out.Body, m.Object.Bytes+1), encoded))
	if err != nil {
		return m, ErrIntegrity
	}
	logical := sha256.New()
	n, readErr := io.Copy(logical, io.LimitReader(z, m.LogicalBytes+1))
	closeErr := z.Close()
	if readErr != nil || closeErr != nil || n != m.LogicalBytes || encoded.N != m.Object.Bytes || hex.EncodeToString(logical.Sum(nil)) != m.LogicalSHA256 || hex.EncodeToString(encoded.H.Sum(nil)) != m.Object.SHA256 {
		return m, ErrIntegrity
	}
	return m, nil
}

// AbortObservation reports current provider absence, not proof that a prior
// in-flight request can never finish. The controller retains reservations until
// its writer/worker fence and active cleanup have independently been verified.
func (s Storage) AbortObservation(ctx context.Context, u Upload) (bool, error) {
	if !s.Gate.Enabled {
		return false, ErrDisabled
	}
	if !u.valid() || u.ID == "" {
		return false, ErrInvalid
	}
	_, err := s.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(s.Bucket), Key: aws.String(u.Object.key(false)), UploadId: aws.String(u.ID), ExpectedBucketOwner: aws.String(s.Account)}, noS3Retry)
	if err != nil && !missing(err) {
		return false, ErrCleanup
	}
	_, err = s.Client.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String(s.Bucket), Key: aws.String(u.Object.key(false)), UploadId: aws.String(u.ID), ExpectedBucketOwner: aws.String(s.Account), MaxParts: aws.Int32(1)}, noS3Retry)
	if !missing(err) {
		return false, ErrCleanup
	}
	return true, nil
}
func (s Storage) DeleteObservation(ctx context.Context, ref Object, result bool) (bool, error) {
	if !s.Gate.Enabled {
		return false, ErrDisabled
	}
	if !ref.valid() || result != (ref.Slot == "result") {
		return false, ErrInvalid
	}
	_, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(ref.key(result)), ExpectedBucketOwner: aws.String(s.Account), IfMatch: aws.String(ref.ETag)}, noS3Retry)
	if err != nil && !missing(err) {
		return false, ErrCleanup
	}
	_, err = s.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(ref.key(result)), ExpectedBucketOwner: aws.String(s.Account)}, noS3Retry)
	if !missing(err) {
		return false, ErrCleanup
	}
	return true, nil
}

// ReadPaidRange is broker-only; there is deliberately no presigned GET API.
// The caller must hold this exact durable job's charged download lease.
func (s Storage) ReadPaidRange(ctx context.Context, permit *DownloadPermit, now int64) (io.ReadCloser, error) {
	if !s.Gate.Enabled {
		return nil, ErrDisabled
	}
	if permit == nil || !permit.used.CompareAndSwap(false, true) {
		return nil, ErrConflict
	}
	j := permit.job
	start, end := j.DownloadStart, j.DownloadEnd
	if j.Financial != "PAID" || j.Artifact != "RETRIEVABLE" || j.Result == nil || !j.Result.Valid() || !j.DownloadClaimed || j.DownloadUntil <= now || j.ResultUntil <= now || start < 0 || end < start || end >= j.Result.Object.Bytes {
		return nil, ErrConflict
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(min(j.DownloadUntil, j.ResultUntil)-now)*time.Second)
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()
	out, err := s.Client.GetObject(bounded, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(j.Result.Object.key(true)), ExpectedBucketOwner: aws.String(s.Account), IfMatch: aws.String(j.Result.Object.ETag), Range: aws.String("bytes=" + strconv.FormatInt(start, 10) + "-" + strconv.FormatInt(end, 10))}, noS3Retry)
	if err != nil {
		return nil, ErrUnknown
	}
	if aws.ToInt64(out.ContentLength) != end-start+1 || aws.ToString(out.ETag) != j.Result.Object.ETag || out.VersionId != nil || aws.ToString(out.ContentRange) != fmt.Sprintf("bytes %d-%d/%d", start, end, j.Result.Object.Bytes) {
		out.Body.Close()
		return nil, ErrIntegrity
	}
	success = true
	return &limitedBody{Reader: io.LimitReader(out.Body, end-start+1), Closer: out.Body, cancel: cancel}, nil
}

type limitedBody struct {
	io.Reader
	io.Closer
	cancel context.CancelFunc
}

func (b *limitedBody) Close() error { b.cancel(); return b.Closer.Close() }

// RecoverBegin reads only the exact reserved key. Never creates a replacement
// MPU when the initial creation response was uncertain. Zero/multiple matches
// require cleanup/operator reconciliation, not a new billable upload.
func (s Storage) RecoverBegin(ctx context.Context, u Upload) (Upload, error) {
	if !s.Gate.Enabled {
		return u, ErrDisabled
	}
	if !u.valid() || u.ID != "" {
		return u, ErrInvalid
	}
	page, err := s.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(s.Bucket), Prefix: aws.String(u.Object.key(false)), ExpectedBucketOwner: aws.String(s.Account), MaxUploads: aws.Int32(2)}, noS3Retry)
	if err != nil || aws.ToBool(page.IsTruncated) {
		return u, ErrUnknown
	}
	for _, m := range page.Uploads {
		if aws.ToString(m.Key) == u.Object.key(false) {
			if u.ID != "" || aws.ToString(m.UploadId) == "" {
				return u, ErrUnknown
			}
			u.ID = *m.UploadId
		}
	}
	if u.ID == "" {
		return u, ErrUnknown
	}
	return u, nil
}

// EraseAndVerify lists both owned prefixes, including orphaned MPUs from lost
// create replies. Requires the writer fence first. Pagination/extra artifacts
// fail closed rather than widening a deletion to another job or unbounded scan.
func (s Storage) EraseAndVerify(ctx context.Context, j Job) error {
	if !s.Gate.Enabled {
		return ErrDisabled
	}
	if !opaque(j.ID) {
		return ErrInvalid
	}
	for _, prefix := range []string{"inputs/" + j.ID + "/", "results/" + j.ID + "/"} {
		owned := func(k string) bool { return strings.HasPrefix(k, prefix) && opaque(strings.TrimPrefix(k, prefix)) }
		mp, e := s.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(s.Bucket), Prefix: aws.String(prefix), ExpectedBucketOwner: aws.String(s.Account), MaxUploads: aws.Int32(5)}, noS3Retry)
		if e != nil || aws.ToBool(mp.IsTruncated) || len(mp.Uploads) > 4 {
			return ErrCleanup
		}
		for _, u := range mp.Uploads {
			if !owned(aws.ToString(u.Key)) || aws.ToString(u.UploadId) == "" {
				return ErrCleanup
			}
			if _, e = s.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(s.Bucket), Key: u.Key, UploadId: u.UploadId, ExpectedBucketOwner: aws.String(s.Account)}, noS3Retry); e != nil && !missing(e) {
				return ErrCleanup
			}
		}
		objects, e := s.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(s.Bucket), Prefix: aws.String(prefix), ExpectedBucketOwner: aws.String(s.Account), MaxKeys: aws.Int32(5)}, noS3Retry)
		if e != nil || aws.ToBool(objects.IsTruncated) || len(objects.Contents) > 4 {
			return ErrCleanup
		}
		for _, o := range objects.Contents {
			if !owned(aws.ToString(o.Key)) || aws.ToString(o.ETag) == "" {
				return ErrCleanup
			}
			if _, e = s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.Bucket), Key: o.Key, IfMatch: o.ETag, ExpectedBucketOwner: aws.String(s.Account)}, noS3Retry); e != nil && !missing(e) {
				return ErrCleanup
			}
		}
		mp, e = s.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(s.Bucket), Prefix: aws.String(prefix), ExpectedBucketOwner: aws.String(s.Account), MaxUploads: aws.Int32(1)}, noS3Retry)
		if e != nil || aws.ToBool(mp.IsTruncated) || len(mp.Uploads) != 0 {
			return ErrCleanup
		}
		objects, e = s.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(s.Bucket), Prefix: aws.String(prefix), ExpectedBucketOwner: aws.String(s.Account), MaxKeys: aws.Int32(1)}, noS3Retry)
		if e != nil || aws.ToBool(objects.IsTruncated) || len(objects.Contents) != 0 {
			return ErrCleanup
		}
	}
	return nil
}
