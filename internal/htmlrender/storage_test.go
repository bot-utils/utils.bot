package htmlrender

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type trackedBody struct {
	io.Reader
	read, closed int
}

func (r *trackedBody) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.read += n
	return n, err
}
func (r *trackedBody) Close() error { r.closed++; return nil }

type objectReaderFunc func(context.Context, string, string) (io.ReadCloser, *int64, error)

func (f objectReaderFunc) OpenObject(ctx context.Context, bucket, key string) (io.ReadCloser, *int64, error) {
	return f(ctx, bucket, key)
}

func TestThreatObjectReadingIsBoundedAndAlwaysCloses(t *testing.T) {
	for _, mode := range []string{"valid", "oversized-header", "oversized-stream", "negative-size", "reader-error"} {
		t.Run(mode, func(t *testing.T) {
			body := &trackedBody{Reader: strings.NewReader("threat-data")}
			var length *int64
			var failure error
			switch mode {
			case "oversized-header":
				n := int64(1 << 30)
				length = &n
			case "negative-size":
				n := int64(-1)
				length = &n
			case "reader-error":
				failure = errors.New("private-reader-error")
			}
			limit := 64
			if mode == "oversized-stream" {
				limit = 4
			}
			reader := objectReaderFunc(func(_ context.Context, bucket, key string) (io.ReadCloser, *int64, error) {
				if bucket != "public-threat-bucket" || key != "hash-prefix" {
					t.Fatal("object scope changed")
				}
				return body, length, failure
			})
			data, err := readObject(context.Background(), reader, "public-threat-bucket", "hash-prefix", limit)
			if mode == "valid" {
				if err != nil || string(data) != "threat-data" {
					t.Fatal("valid object rejected", err)
				}
			} else if !errors.Is(err, ErrThreats) || len(data) != 0 {
				t.Fatal("invalid object returned data", mode, err)
			}
			if body.closed != 1 || body.read > limit+1 {
				t.Fatal("unbounded read or unclosed object", body.read, body.closed)
			}
			if (mode == "oversized-header" || mode == "negative-size" || mode == "reader-error") && body.read != 0 {
				t.Fatal("read body after failed metadata check")
			}
		})
	}
}
