package csvcloud

import (
	"context"
	"encoding/json"
	"errors"
	"pdfservice/internal/jsonwire"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

var AbsentBucketPolicyHash = Hash([]byte("absent-bucket-policy-v1"))

type BucketControl interface {
	S3API
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketOwnershipControls(context.Context, *s3.GetBucketOwnershipControlsInput, ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	GetBucketReplication(context.Context, *s3.GetBucketReplicationInput, ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	DeleteBucket(context.Context, *s3.DeleteBucketInput, ...func(*s3.Options)) (*s3.DeleteBucketOutput, error)
}
type BucketReader interface {
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

func apiCode(e error, code string) bool {
	var a smithy.APIError
	return errors.As(e, &a) && a.ErrorCode() == code
}

// BucketAbsence executes only in the independent read-only verifier. Ambiguous
// HEAD/403/list results are not absence. A 15-second converged absence window with bounded backoff
// is necessary; AWS late-PUT behavior still requires cloud validation.
type BucketAbsence struct {
	Client          BucketReader
	Bucket, Account string
	now             func() time.Time
	wait            func(context.Context, time.Duration) error
}

func (v BucketAbsence) Verify(ctx context.Context) error {
	if v.Client == nil || v.Bucket == "" || v.Account == "" {
		return ErrCleanup
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	wait := func(c context.Context, d time.Duration) error {
		select {
		case <-c.Done():
			return c.Err()
		case <-time.After(d):
			return nil
		}
	}
	if v.wait != nil {
		wait = v.wait
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	until := now().Add(30 * time.Second)
	var absentSince time.Time
	consecutive := 0
	pause := 500 * time.Millisecond
	for now().Before(until) {
		_, e := v.Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(v.Bucket), ExpectedBucketOwner: aws.String(v.Account)}, noS3Retry)
		if apiCode(e, "NoSuchBucket") {
			if absentSince.IsZero() {
				absentSince = now()
			}
			consecutive++
			if consecutive >= 3 && now().Sub(absentSince) >= 15*time.Second {
				return nil
			}
		} else if e != nil || !absentSince.IsZero() {
			return ErrCleanup
		}
		if wait(ctx, pause) != nil {
			return ErrCleanup
		}
		pause *= 2
		if pause > 4*time.Second {
			pause = 4 * time.Second
		}
	}
	return ErrCleanup
}

// RunFence is a destructive synthetic-only fence. It is invoked by the
// controller, never inside the broker it stops. One unique never-reused bucket
// belongs to one run/job. Runtime writer roles have no CreateBucket permission.
type RunFence struct {
	Repo                     Repository
	Storage                  Storage
	Control                  BucketControl
	VerifyBucket             func(context.Context) error      // separate read-only process/identity
	StopWriters              func(context.Context, Job) error // original broker AND worker + ENIs
	RunID, JobID, PolicyHash string
	SyntheticOnly            bool
}

func (f RunFence) valid(j Job) bool {
	return f.SyntheticOnly && opaque(f.RunID) && j.ID == f.JobID && opaque(f.JobID) && opaque(f.PolicyHash) && f.Control != nil && f.VerifyBucket != nil && f.StopWriters != nil && f.Storage.Bucket == "utils-csv-"+f.Storage.Account+"-"+f.RunID[:24] && (j.Artifact == "PROCESSING_UNKNOWN" || j.Artifact == "DELETING")
}
func (f RunFence) journal(ctx context.Context, phase string, validUntil ...int64) error {
	pk := "FENCE/" + f.RunID
	old, e := f.Repo.get(ctx, pk)
	if e != nil {
		return e
	}
	version := int64(1)
	condition := "attribute_not_exists(pk)"
	var values map[string]d.AttributeValue
	var names map[string]string
	if len(old) != 0 {
		if av, ok := old["version"].(*d.AttributeValueMemberN); ok {
			version = parseVersion(av.Value) + 1
			if version < 2 || version > 64 {
				return ErrCleanup
			}
		} else {
			return ErrCleanup
		}
		condition = "#v = :v"
		values = map[string]d.AttributeValue{":v": num(version - 1)}
		names = map[string]string{"#v": "version"}
		if av, ok := old["phase"].(*d.AttributeValueMemberS); !ok || phase == "SEALING" && av.Value != "SEALING" {
			return ErrCleanup
		}
	}
	item := map[string]d.AttributeValue{"pk": str(pk), "version": num(version), "phase": str(phase), "bucket": str(f.Storage.Bucket), "job": str(f.JobID)}
	if phase == "CONFIRMED" {
		if len(validUntil) != 1 || validUntil[0] <= time.Now().Unix() {
			return ErrCleanup
		}
		item["verified_until"] = num(validUntil[0])
	}
	return f.Repo.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(f.Repo.Table), Item: item, ConditionExpression: aws.String(condition), ExpressionAttributeNames: names, ExpressionAttributeValues: values}}})
}
func (f RunFence) VerifyStopped(ctx context.Context, j Job) error {
	if !f.valid(j) {
		return ErrCleanup
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	row, e := f.Repo.get(ctx, "FENCE/"+f.RunID)
	if e != nil {
		return ErrCleanup
	}
	phase := ""
	if len(row) != 0 {
		p, ok := row["phase"].(*d.AttributeValueMemberS)
		b, bok := row["bucket"].(*d.AttributeValueMemberS)
		id, iok := row["job"].(*d.AttributeValueMemberS)
		if !ok || !bok || !iok || b.Value != f.Storage.Bucket || id.Value != j.ID {
			return ErrCleanup
		}
		phase = p.Value
	}
	if phase == "CONFIRMED" {
		if expiry, ok := row["verified_until"].(*d.AttributeValueMemberN); ok && time.Now().Unix() < parseVersion(expiry.Value) {
			return nil
		}
	}
	if phase == "CONFIRMED" || phase == "DELETED" {
		started := time.Now().Unix()
		if f.VerifyBucket(ctx) != nil || time.Now().Unix() >= started+30 {
			return ErrCleanup
		}
		return f.journal(ctx, "CONFIRMED", started+30)
	}

	if phase != "" && phase != "SEALING" {
		return ErrCleanup
	}
	if f.StopWriters(ctx, j) != nil {
		return ErrCleanup
	}
	if f.checkBucket(ctx) != nil {
		return ErrCleanup
	}
	if f.journal(ctx, "SEALING") != nil {
		return ErrCleanup
	}
	// Inspect the root before deleting: unknown foreign keys/MPUs block the run.
	if f.onlyOwned(ctx, j) != nil || f.Storage.EraseAndVerify(ctx, j) != nil {
		return ErrCleanup
	}
	if _, e = f.Control.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(f.Storage.Bucket), ExpectedBucketOwner: aws.String(f.Storage.Account)}, noS3Retry); e != nil {
		return ErrCleanup
	}
	if f.journal(ctx, "DELETED") != nil {
		return ErrCleanup
	}
	// Yield after the destructive phase. A later bounded recovery claim performs
	// convergence without repeating task stop or bucket deletion work.
	return ErrCleanup
}
func (f RunFence) EraseAndVerify(ctx context.Context, j Job) error {
	if !f.valid(j) {
		return ErrCleanup
	}
	row, e := f.Repo.get(ctx, "FENCE/"+f.RunID)
	if e != nil {
		return ErrCleanup
	}
	phase, ok := row["phase"].(*d.AttributeValueMemberS)
	bucket, bok := row["bucket"].(*d.AttributeValueMemberS)
	id, iok := row["job"].(*d.AttributeValueMemberS)
	if !ok || !bok || !iok || phase.Value != "CONFIRMED" || bucket.Value != f.Storage.Bucket || id.Value != j.ID {
		return ErrCleanup
	}
	expiry, ok := row["verified_until"].(*d.AttributeValueMemberN)
	if !ok || time.Now().Unix() >= parseVersion(expiry.Value) {
		return ErrCleanup
	}
	return nil
}

func (f RunFence) onlyOwned(ctx context.Context, j Job) error {
	owned := func(k string) bool {
		for _, prefix := range []string{"inputs/" + j.ID + "/", "results/" + j.ID + "/"} {
			if strings.HasPrefix(k, prefix) && opaque(strings.TrimPrefix(k, prefix)) {
				return true
			}
		}
		return false
	}
	objects, e := f.Control.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(f.Storage.Bucket), ExpectedBucketOwner: aws.String(f.Storage.Account), MaxKeys: aws.Int32(5)}, noS3Retry)
	if e != nil || objects == nil || aws.ToBool(objects.IsTruncated) || len(objects.Contents) > 4 {
		return ErrCleanup
	}
	for _, o := range objects.Contents {
		if !owned(aws.ToString(o.Key)) {
			return ErrCleanup
		}
	}
	mp, e := f.Control.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(f.Storage.Bucket), ExpectedBucketOwner: aws.String(f.Storage.Account), MaxUploads: aws.Int32(5)}, noS3Retry)
	if e != nil || mp == nil || aws.ToBool(mp.IsTruncated) || len(mp.Uploads) > 4 {
		return ErrCleanup
	}
	for _, u := range mp.Uploads {
		if !owned(aws.ToString(u.Key)) {
			return ErrCleanup
		}
	}
	return nil
}
func (f RunFence) checkBucket(ctx context.Context) error {
	bucket, owner := aws.String(f.Storage.Bucket), aws.String(f.Storage.Account)
	b, e := f.Control.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry)
	if e != nil || b == nil || b.PublicAccessBlockConfiguration == nil {
		return ErrCleanup
	}
	p := b.PublicAccessBlockConfiguration
	if !aws.ToBool(p.BlockPublicAcls) || !aws.ToBool(p.BlockPublicPolicy) || !aws.ToBool(p.IgnorePublicAcls) || !aws.ToBool(p.RestrictPublicBuckets) {
		return ErrCleanup
	}
	ownership, e := f.Control.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry)
	if e != nil || ownership == nil || ownership.OwnershipControls == nil || len(ownership.OwnershipControls.Rules) != 1 || ownership.OwnershipControls.Rules[0].ObjectOwnership != st.ObjectOwnershipBucketOwnerEnforced {
		return ErrCleanup
	}
	acl, e := f.Control.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry)
	if e != nil || acl == nil || acl.Owner == nil || aws.ToString(acl.Owner.ID) == "" || len(acl.Grants) != 1 || acl.Grants[0].Permission != st.PermissionFullControl || acl.Grants[0].Grantee == nil || aws.ToString(acl.Grants[0].Grantee.ID) != aws.ToString(acl.Owner.ID) || acl.Grants[0].Grantee.Type != st.TypeCanonicalUser {
		return ErrCleanup
	}
	version, e := f.Control.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry)
	if e != nil || version == nil || version.Status != "" || version.MFADelete != "" {
		return ErrCleanup
	}
	if _, e = f.Control.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry); !apiCode(e, "ObjectLockConfigurationNotFoundError") {
		return ErrCleanup
	}
	if _, e = f.Control.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry); !apiCode(e, "ReplicationConfigurationNotFoundError") {
		return ErrCleanup
	}
	encryption, e := f.Control.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry)
	if e != nil || encryption == nil || encryption.ServerSideEncryptionConfiguration == nil || len(encryption.ServerSideEncryptionConfiguration.Rules) != 1 {
		return ErrCleanup
	}
	rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil || rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != st.ServerSideEncryptionAes256 {
		return ErrCleanup
	}
	policy, e := f.Control.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: bucket, ExpectedBucketOwner: owner}, noS3Retry)
	if apiCode(e, "NoSuchBucketPolicy") && f.PolicyHash == AbsentBucketPolicyHash {
		return nil
	}
	if e != nil || policy == nil || f.PolicyHash == AbsentBucketPolicyHash {
		return ErrCleanup
	}

	var value any
	raw := []byte(aws.ToString(policy.Policy))
	if len(raw) > 64<<10 || jsonwire.Decode(raw, &value, 64<<10) != nil {
		return ErrCleanup
	}
	canonical, _ := json.Marshal(value)
	if Hash(canonical) != f.PolicyHash {
		return ErrCleanup
	}
	return nil
}
