package csvcloud

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"net/http"
	"strings"
	"testing"
	"time"
)

type bucketModel struct {
	deleted, late, denied, wrongPolicy, extra, versioned bool
	objects                                              map[string]bool
	deletes, reads, stops                                int
}

func (m *bucketModel) request(req *http.Request) (*http.Response, error) {
	q := req.URL.Query()
	errResponse := func(code string, status int) (*http.Response, error) {
		return response(status, "<Error><Code>"+code+"</Code></Error>", nil), nil
	}
	if q.Has("location") {
		m.reads++
		if m.denied {
			return errResponse("AccessDenied", 403)
		}
		if m.deleted {
			return errResponse("NoSuchBucket", 404)
		}
		return response(200, `<LocationConstraint>us-east-2</LocationConstraint>`, nil), nil
	}
	if req.Method == "DELETE" && req.URL.Path == "/" {
		m.deletes++
		if m.late {
			m.late = false
			for key := range m.objects {
				m.objects[key] = true
				break
			}
			if len(m.objects) == 0 {
				m.objects["late"] = true
			}
			return errResponse("BucketNotEmpty", 409)
		}
		for _, present := range m.objects {
			if present {
				return errResponse("BucketNotEmpty", 409)
			}
		}
		m.deleted = true
		return response(204, "", nil), nil
	}
	if m.deleted {
		return errResponse("NoSuchBucket", 404)
	}
	if q.Has("publicAccessBlock") {
		return response(200, `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`, nil), nil
	}
	if q.Has("ownershipControls") {
		return response(200, `<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>`, nil), nil
	}
	if q.Has("acl") {
		return response(200, `<AccessControlPolicy><Owner><ID>owner</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>owner</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`, nil), nil
	}
	if q.Has("versioning") {
		body := `<VersioningConfiguration/>`
		if m.versioned {
			body = `<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`
		}
		return response(200, body, nil), nil
	}
	if q.Has("object-lock") {
		return errResponse("ObjectLockConfigurationNotFoundError", 404)
	}
	if q.Has("replication") {
		return errResponse("ReplicationConfigurationNotFoundError", 404)
	}
	if q.Has("encryption") {
		return response(200, `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`, nil), nil
	}
	if q.Has("policy") {
		body := `{}`
		if m.wrongPolicy {
			body = `{"extra":true}`
		}
		return response(200, body, nil), nil
	}
	if q.Has("uploads") {
		return response(200, `<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>`, nil), nil
	}
	if q.Get("list-type") == "2" {
		body := `<ListBucketResult><IsTruncated>false</IsTruncated>`
		prefix := q.Get("prefix")
		for key, present := range m.objects {
			if present && strings.HasPrefix(key, prefix) {
				body += `<Contents><Key>` + key + `</Key><ETag>owned</ETag><Size>1</Size></Contents>`
			}
		}
		if m.extra && prefix == "" {
			body += `<Contents><Key>foreign/key</Key><ETag>foreign</ETag><Size>1</Size></Contents>`
		}
		body += `</ListBucketResult>`
		return response(200, body, nil), nil
	}
	if req.Method == "DELETE" {
		m.objects[strings.TrimPrefix(req.URL.Path, "/")] = false
		return response(204, "", nil), nil
	}
	return nil, fmt.Errorf("unexpected synthetic operation")
}
func fenceFixture(t *testing.T) (RunFence, Job, *bucketModel) {
	t.Helper()
	repo, _ := memoryRepo()
	j := fixtureJob()
	seed(t, repo, j)
	old := j
	j.Version++
	j.Artifact = "DELETING"
	if repo.Replace(ctx, old, j) != nil {
		t.Fatal("deletion fixture")
	}
	run := ID()
	model := &bucketModel{objects: map[string]bool{"inputs/" + j.ID + "/" + ID(): true, "results/" + j.ID + "/" + ID(): true}}
	config := sdkConfig(model.request)
	control := s3.NewFromConfig(config)
	s := Storage{Client: control, Bucket: "utils-csv-123456789012-" + run[:24], Account: "123456789012", Gate: Gate{Enabled: true}}
	// Separate SDK client is the verifier; production uses a separate process and
	// read-only role. This fake transport only models AWS behavior, not propagation.
	clock := fixtureTime
	independent := BucketAbsence{Client: s3.NewFromConfig(config), Bucket: s.Bucket, Account: s.Account, now: func() time.Time { return clock }, wait: func(_ context.Context, d time.Duration) error { clock = clock.Add(d); return nil }}
	return RunFence{Repo: repo, Storage: s, Control: control, VerifyBucket: independent.Verify, StopWriters: func(context.Context, Job) error { model.stops++; return nil }, RunID: run, JobID: j.ID, PolicyHash: Hash([]byte(`{}`)), SyntheticOnly: true}, j, model
}
func TestRunFenceRequiresPhysicalDeletionAndIndependentAbsence(t *testing.T) {
	f, j, m := fenceFixture(t)
	cleanup := Cleanup{Repo: f.Repo, Writers: f, Objects: f, Gate: Gate{Enabled: true}}
	if e := cleanup.Complete(ctx, j.ID); e != ErrCleanup {
		t.Fatal("seal must yield before convergence", e)
	}
	if e := cleanup.Complete(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	if !m.deleted || m.deletes != 1 || m.stops != 1 || m.reads < 3 || readJob(t, f.Repo, j.ID).Artifact != "ERASED" {
		t.Fatal("missing physical fence")
	}
	if cleanup.Complete(ctx, j.ID) != nil || m.deletes != 1 {
		t.Fatal("duplicate destructive cleanup")
	}
}
func TestRunFenceKeepsCapacityOnLatePUTAndAmbiguousAbsence(t *testing.T) {
	for _, scenario := range []string{"late", "denied", "policy", "foreign", "versioned"} {
		t.Run(scenario, func(t *testing.T) {
			f, j, m := fenceFixture(t)
			switch scenario {
			case "late":
				m.late = true
			case "denied":
				m.denied = true
			case "policy":
				m.wrongPolicy = true
			case "foreign":
				m.extra = true
			case "versioned":
				m.versioned = true
			}
			c := Cleanup{Repo: f.Repo, Writers: f, Objects: f, Gate: Gate{Enabled: true}}
			if c.Complete(ctx, j.ID) != ErrCleanup || readJob(t, f.Repo, j.ID).Artifact == "ERASED" {
				t.Fatal("ambiguous fence accepted")
			}
			memory := f.Repo.Client.(*memoryDynamo)
			if avs(memory.rows["CAPACITY"]["used"]) != "1" {
				t.Fatal("unknown capacity released")
			}
			if scenario == "late" {
				if c.Complete(ctx, j.ID) != ErrCleanup {
					t.Fatal("delete must remain pending proof")
				}
				if c.Complete(ctx, j.ID) != nil || !m.deleted {
					t.Fatal("late orphan not reaped")
				}
			}
		})
	}
}
func TestBucketAbsenceNeverAccepts403OrLiveBucket(t *testing.T) {
	for _, scenario := range []string{"live", "403"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, m := fenceFixture(t)
			m.denied = scenario == "403"
			client := s3.NewFromConfig(sdkConfig(m.request))
			clock := fixtureTime
			v := BucketAbsence{Client: client, Bucket: "synthetic", Account: "123456789012", now: func() time.Time { return clock }, wait: func(_ context.Context, d time.Duration) error { clock = clock.Add(d); return nil }}
			bounded, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			if v.Verify(bounded) == nil {
				t.Fatal("missing permission or live bucket treated as absent")
			}
		})
	}
}
func TestQuotedNeverSettledResultErasesAsUnpaid(t *testing.T) {
	p, j, q, _, _ := processorFixture(t)
	if p.Process(ctx, j.ID, q) != nil {
		t.Fatal("fixture")
	}
	old := readJob(t, p.Repo, j.ID)
	next := copyJob(old)
	next.Version++
	next.Artifact = "DELETING"
	if p.Repo.Replace(ctx, old, next) != nil {
		t.Fatal("deletion")
	}
	c := Cleanup{Repo: p.Repo, Writers: &fenceStub{}, Objects: &eraseStub{}, Gate: Gate{Enabled: true}}
	if c.Complete(ctx, j.ID) != nil || readJob(t, p.Repo, j.ID).Financial != "UNPAID" {
		t.Fatal("expired quoted result stuck")
	}
}

func TestBucketVerifierWaitsForConvergenceAndRejectsLateVisibility(t *testing.T) {
	for _, scenario := range []string{"delayed_visibility", "late_after_absence", "never_converges"} {
		t.Run(scenario, func(t *testing.T) {
			clock := fixtureTime
			calls := 0
			config := sdkConfig(func(*http.Request) (*http.Response, error) {
				calls++
				live := scenario == "delayed_visibility" && calls <= 2 || scenario == "late_after_absence" && calls >= 3 || scenario == "never_converges"
				if live {
					return response(200, `<LocationConstraint>us-east-2</LocationConstraint>`, nil), nil
				}
				return response(404, `<Error><Code>NoSuchBucket</Code></Error>`, nil), nil
			})
			v := BucketAbsence{Client: s3.NewFromConfig(config), Bucket: "synthetic", Account: "123456789012", now: func() time.Time { return clock }, wait: func(_ context.Context, d time.Duration) error { clock = clock.Add(d); return nil }}
			e := v.Verify(ctx)
			if (e == nil) != (scenario == "delayed_visibility") {
				t.Fatal("uncertain convergence accepted", e)
			}
			if e == nil && (clock.Sub(fixtureTime) < 15*time.Second || calls < 5) {
				t.Fatal("premature absence")
			}
		})
	}
}
func TestLatePutAfterSuccessfulDeleteKeepsReservationOnContradiction(t *testing.T) {
	f, j, m := fenceFixture(t)
	clock := fixtureTime
	checks := 0
	config := sdkConfig(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Has("location") && m.deleted {
			checks++
			if checks == 3 {
				return response(200, `<LocationConstraint>us-east-2</LocationConstraint>`, nil), nil
			}
		}
		return m.request(req)
	})
	verifier := BucketAbsence{Client: s3.NewFromConfig(config), Bucket: f.Storage.Bucket, Account: f.Storage.Account, now: func() time.Time { return clock }, wait: func(_ context.Context, d time.Duration) error { clock = clock.Add(d); return nil }}
	f.VerifyBucket = verifier.Verify
	c := Cleanup{Repo: f.Repo, Writers: f, Objects: f, Gate: Gate{Enabled: true}}
	if c.Complete(ctx, j.ID) != ErrCleanup || !m.deleted || readJob(t, f.Repo, j.ID).Artifact == "ERASED" {
		t.Fatal("late contradictory visibility accepted")
	}
	memory := f.Repo.Client.(*memoryDynamo)
	if avs(memory.rows["CAPACITY"]["used"]) != "1" {
		t.Fatal("capacity released before proof")
	}
	if c.Complete(ctx, j.ID) != ErrCleanup || readJob(t, f.Repo, j.ID).Artifact == "ERASED" {
		t.Fatal("contradictory convergence accepted")
	}
	// Stale writer cannot recreate the never-reused bucket; a post-delete PUT
	// returns NoSuchBucket. Actual AWS behavior remains a required separate gate.
	stale := s3.NewFromConfig(sdkConfig(m.request))
	_, e := stale.PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Storage.Bucket, Key: ptrResultKey(j.ID), Body: strings.NewReader("late")}, noS3Retry)
	if !apiCode(e, "NoSuchBucket") {
		t.Fatal("stale write survived physical deletion")
	}
}
func ptrResultKey(id string) *string { key := "results/" + id + "/" + ID(); return &key }
