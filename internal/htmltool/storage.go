package htmltool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"pdfservice/internal/htmlrender"
)

type SnapshotReader interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}
type SnapshotWriter interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}
type objectReader struct{ client SnapshotReader }

func (s objectReader) OpenObject(ctx context.Context, bucket, key string) (io.ReadCloser, *int64, error) {
	object, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil || object == nil || object.Body == nil {
		if object != nil && object.Body != nil {
			object.Body.Close()
		}
		return nil, nil, ErrThreats
	}
	return object.Body, object.ContentLength, nil
}
func LoadSnapshot(ctx context.Context, reader SnapshotReader, bucket string, now time.Time) (*RemoteSnapshot, error) {
	return htmlrender.LoadSnapshot(ctx, objectReader{reader}, bucket, now)
}

func SaveSnapshot(ctx context.Context, client SnapshotWriter, bucket string, data []byte, now time.Time) error {
	_, err := DecodeSnapshot(data, now)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	m := manifest{Version: 2, Generation: hex.EncodeToString(digest[:]), Refreshed: int64(binary.BigEndian.Uint64(data[8:16])), Shards: make([]shardInfo, shardCount)}
	shards := make([][]byte, shardCount)
	hashes := data[56:] // DecodeSnapshot validated the entire header and payload.
	offset := 0
	for prefix := range shardCount {
		start := offset
		for offset < len(hashes) && int(hashes[offset]) == prefix {
			offset += 32
		}
		shard := hashes[start:offset]
		if len(shard)/32 > maxShardEntries {
			return ErrThreats
		}
		sum := sha256.Sum256(shard)
		m.Shards[prefix] = shardInfo{Entries: len(shard) / 32, SHA256: hex.EncodeToString(sum[:])}
		shards[prefix] = shard
	}
	// Bounded parallel writes keep the refresh short without a goroutine/object.
	writeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var next atomic.Int32
	var failed atomic.Bool
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for writeCtx.Err() == nil {
				prefix := int(next.Add(1)) - 1
				if prefix >= shardCount {
					return
				}
				_, err := client.PutObject(writeCtx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(shardKey(m.Generation, byte(prefix))), Body: bytes.NewReader(shards[prefix]), ContentType: aws.String("application/octet-stream"), ServerSideEncryption: "AES256"})
				if err != nil {
					failed.Store(true)
					cancel()
					return
				}
			}
		})
	}
	workers.Wait()
	if failed.Load() || ctx.Err() != nil {
		return ErrThreats
	}
	body, err := json.Marshal(m)
	if err != nil || len(body) > maxManifest {
		return ErrThreats
	}
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(SnapshotKey), Body: bytes.NewReader(body), ContentType: aws.String("application/json"), ServerSideEncryption: "AES256", Metadata: map[string]string{"shards": strconv.Itoa(shardCount)}})
	if err != nil {
		return ErrThreats
	}
	return nil
}
