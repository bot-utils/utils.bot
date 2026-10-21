package htmlrender

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"pdfservice/internal/jsonwire"
)

const SnapshotKey = "threats/v2/current.json"
const GenerationPrefix = "threats/v2/generations/"
const ShardCount = 256
const MaxShardEntries = 32768
const MaxManifest = 64 << 10

// Every generation is immutable. Publish the small manifest LAST, so readers
// never combine an old index with new shards or see an incomplete refresh.
type ShardInfo struct {
	Entries int    `json:"entries"`
	SHA256  string `json:"sha256"`
}
type Manifest struct {
	Version    int         `json:"version"`
	Generation string      `json:"generation"`
	Refreshed  int64       `json:"refreshed"`
	Shards     []ShardInfo `json:"shards"`
}

// ObjectReader keeps the credential-free runtime independent of cloud SDKs.
type ObjectReader interface {
	OpenObject(context.Context, string, string) (io.ReadCloser, *int64, error)
}

// RemoteSnapshot reads only the hash-prefix shards needed by this job. It never
// sends a customer URL/hostname to S3: object keys contain public generation and
// hash-prefix identifiers only. The cache lives only in this isolated worker.
type RemoteSnapshot struct {
	client   ObjectReader
	bucket   string
	manifest Manifest
	shards   map[byte][]byte
}

func readObject(ctx context.Context, client ObjectReader, bucket, key string, max int) ([]byte, error) {
	body, size, err := client.OpenObject(ctx, bucket, key)
	if body != nil {
		defer body.Close()
	}
	if err != nil || body == nil {
		return nil, ErrThreats
	}
	if size != nil && (*size < 0 || *size > int64(max)) {
		return nil, ErrThreats
	}
	b, err := io.ReadAll(io.LimitReader(body, int64(max)+1))
	if err != nil || len(b) > max {
		return nil, ErrThreats
	}
	return b, nil
}

func LoadSnapshot(ctx context.Context, client ObjectReader, bucket string, now time.Time) (*RemoteSnapshot, error) {
	data, err := readObject(ctx, client, bucket, SnapshotKey, MaxManifest)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if jsonwire.Decode(data, &m, MaxManifest) != nil || m.Version != 2 || len(m.Generation) != 64 || len(m.Shards) != ShardCount {
		return nil, ErrThreats
	}
	if _, err := hex.DecodeString(m.Generation); err != nil || m.Generation != strings.ToLower(m.Generation) {
		return nil, ErrThreats
	}
	if (&Snapshot{refreshed: time.Unix(m.Refreshed, 0)}).fresh(now) != nil {
		return nil, ErrThreats
	}
	total := 0
	for _, s := range m.Shards {
		if s.Entries < 0 || s.Entries > MaxShardEntries || len(s.SHA256) != 64 || s.SHA256 != strings.ToLower(s.SHA256) {
			return nil, ErrThreats
		}
		if _, err := hex.DecodeString(s.SHA256); err != nil {
			return nil, ErrThreats
		}
		total += s.Entries
	}
	if total == 0 || total > MaxDomains {
		return nil, ErrThreats
	}
	return &RemoteSnapshot{client: client, bucket: bucket, manifest: m, shards: make(map[byte][]byte)}, nil
}
func ShardKey(generation string, prefix byte) string {
	return GenerationPrefix + generation + "/" + hex.EncodeToString([]byte{prefix}) + ".bin"
}
func (s *RemoteSnapshot) Check(ctx context.Context, host string, now time.Time) error {
	if s == nil || (&Snapshot{refreshed: time.Unix(s.manifest.Refreshed, 0)}).fresh(now) != nil {
		return ErrThreats
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !domainName(host) {
		return ErrBlocked
	}
	for strings.Contains(host, ".") {
		if ctx.Err() != nil {
			return ErrThreats
		}
		hash := sha256.Sum256([]byte(host))
		prefix := hash[0]
		data, ok := s.shards[prefix]
		if !ok {
			info := s.manifest.Shards[int(prefix)]
			var err error
			data, err = readObject(ctx, s.client, s.bucket, ShardKey(s.manifest.Generation, prefix), info.Entries*32)
			if err != nil || len(data) != info.Entries*32 {
				return ErrThreats
			}
			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != info.SHA256 {
				return ErrThreats
			}
			for i := 0; i < len(data); i += 32 {
				if data[i] != prefix || i > 0 && bytes.Compare(data[i-32:i], data[i:i+32]) >= 0 {
					return ErrThreats
				}
			}
			s.shards[prefix] = data
		}
		if containsHash(data, hash) {
			return ErrBlocked
		}
		host = host[strings.IndexByte(host, '.')+1:]
	}
	return nil
}

// ManifestBytes exposes only the validated public threat metadata.
func (s *RemoteSnapshot) ManifestBytes() []byte { b, _ := json.Marshal(s.manifest); return b }

func (s *RemoteSnapshot) Generation() string { return s.manifest.Generation }
