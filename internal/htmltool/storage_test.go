package htmltool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"pdfservice/internal/htmlrender"
)

type objectStore struct {
	mu        sync.Mutex
	objects   map[string][]byte
	reads     []string
	readBytes int
	writes    int
	failShard bool
}

func (s *objectStore) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, *in.Key)
	data, ok := s.objects[*in.Key]
	if !ok {
		return nil, errors.New("private-storage-error")
	}
	s.readBytes += len(data)
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(append([]byte(nil), data...)))}, nil
}
func (s *objectStore) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failShard && strings.HasSuffix(*in.Key, "/80.bin") {
		return nil, errors.New("private-storage-error")
	}
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	s.writes++
	s.objects[*in.Key], _ = io.ReadAll(in.Body)
	return &s3.PutObjectOutput{}, nil
}
func dataFor(t *testing.T, now time.Time, domains ...string) []byte {
	t.Helper()
	hashes := make([][32]byte, len(domains))
	for i, d := range domains {
		hashes[i] = sha256.Sum256([]byte(d))
	}
	data, err := htmlrender.EncodeSnapshot(hashes, now)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestSnapshotStorageIsAtomicAndNeverPublishesCorruption(t *testing.T) {
	now := time.Now()
	data := dataFor(t, now, "evil.example")
	store := &objectStore{}
	if err := SaveSnapshot(context.Background(), store, "private-bucket", data, now); err != nil || store.writes != 257 {
		t.Fatal(err, store.writes)
	}
	original := append([]byte(nil), store.objects[SnapshotKey]...)
	if _, err := LoadSnapshot(context.Background(), store, "private-bucket", now); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), data...)
	bad[len(bad)-1] ^= 1
	if err := SaveSnapshot(context.Background(), store, "private-bucket", bad, now); err == nil || store.writes != 257 || !bytes.Equal(store.objects[SnapshotKey], original) {
		t.Fatal("published corrupted data")
	}
	store.failShard = true
	next := dataFor(t, now.Add(time.Second), "new.example")
	if err := SaveSnapshot(context.Background(), store, "private-bucket", next, now.Add(time.Second)); err == nil || !bytes.Equal(store.objects[SnapshotKey], original) {
		t.Fatal("published incomplete generation")
	}
}
func TestRemoteThreatChecksReadOnlyNeededShardsAndNeverMixVersions(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := &objectStore{}
	if err := SaveSnapshot(ctx, store, "bucket", dataFor(t, now, "evil.example", "old.example"), now); err != nil {
		t.Fatal(err)
	}
	old, err := LoadSnapshot(ctx, store, "bucket", now)
	if err != nil {
		t.Fatal(err)
	}
	reads := len(store.reads)
	if !errors.Is(old.Check(ctx, "x.evil.example", now), ErrBlocked) {
		t.Fatal("blocked parent missed")
	}
	if len(store.reads) > reads+2 {
		t.Fatal("downloaded unrelated shards", len(store.reads)-reads)
	}
	for _, key := range store.reads {
		if strings.Contains(key, "evil.example") {
			t.Fatal("hostname sent to S3")
		}
	}
	reads = len(store.reads)
	if !errors.Is(old.Check(ctx, "x.evil.example", now), ErrBlocked) || len(store.reads) != reads {
		t.Fatal("job cache ignored")
	}
	if err := SaveSnapshot(ctx, store, "bucket", dataFor(t, now.Add(time.Second), "new.example"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	next, err := LoadSnapshot(ctx, store, "bucket", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(next.Check(ctx, "new.example", now), ErrBlocked) || next.Check(ctx, "old.example", now) != nil {
		t.Fatal("new generation not used")
	}
	if !errors.Is(old.Check(ctx, "old.example", now), ErrBlocked) {
		t.Fatal("in-flight old reader mixed generations")
	}
	if !errors.Is(next.Check(ctx, "example.com", now.Add(25*time.Hour)), ErrThreats) {
		t.Fatal("stale snapshot used")
	}
}
func TestRemoteSnapshotRejectsMissingTruncatedAndCorruptShards(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	for _, kind := range []string{"missing", "corrupt", "oversized", "bad-manifest"} {
		t.Run(kind, func(t *testing.T) {
			store := &objectStore{}
			SaveSnapshot(ctx, store, "bucket", dataFor(t, now, "evil.example"), now)
			var m manifest
			json.Unmarshal(store.objects[SnapshotKey], &m)
			hash := sha256.Sum256([]byte("evil.example"))
			key := shardKey(m.Generation, hash[0])
			switch kind {
			case "missing":
				delete(store.objects, key)
			case "corrupt":
				store.objects[key][3] ^= 1
			case "oversized":
				store.objects[key] = append(store.objects[key], 1)
			case "bad-manifest":
				m.Generation = "../private"
				store.objects[SnapshotKey], _ = json.Marshal(m)
			}
			s, err := LoadSnapshot(ctx, store, "bucket", now)
			if kind == "bad-manifest" {
				if err == nil {
					t.Fatal("manifest escaped prefix")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(s.Check(ctx, "evil.example", now), ErrThreats) {
				t.Fatal("bad shard accepted")
			}
		})
	}
}

func snapshot(t *testing.T, domains ...string) *Snapshot {
	t.Helper()
	s, err := DecodeSnapshot(dataFor(t, time.Now(), domains...), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type failedObject struct{ body io.ReadCloser }

func (s failedObject) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: s.body}, errors.New("private-storage-error")
}

type closeCounter struct{ closed int }

func (c *closeCounter) Read([]byte) (int, error) { return 0, io.EOF }
func (c *closeCounter) Close() error             { c.closed++; return nil }

func TestCloudReaderClosesBodyReturnedWithError(t *testing.T) {
	body := &closeCounter{}
	reader := objectReader{client: failedObject{body: body}}
	data, size, err := reader.OpenObject(context.Background(), "public-threat-bucket", "key")
	if !errors.Is(err, ErrThreats) || data != nil || size != nil || body.closed != 1 {
		t.Fatal("storage error leaked data or body", body.closed, err)
	}
}
