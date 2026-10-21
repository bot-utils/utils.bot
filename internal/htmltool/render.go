package htmltool

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"pdfservice/internal/htmlrender"
)

// The controller owns cloud/payment integration. The disposable renderer owns
// source handling and contains no cloud SDK or payment implementation.
type Input = htmlrender.Input
type Result = htmlrender.Result
type Worker = htmlrender.Worker
type DomainCheck = htmlrender.DomainCheck
type Snapshot = htmlrender.Snapshot
type RemoteSnapshot = htmlrender.RemoteSnapshot
type BrowserFetcher = htmlrender.BrowserFetcher
type Fetcher = htmlrender.Fetcher
type VMServer = htmlrender.VMServer
type VMJob = htmlrender.VMJob
type manifest = htmlrender.Manifest
type shardInfo = htmlrender.ShardInfo

const (
	Path             = htmlrender.Path
	MaxRequest       = htmlrender.MaxRequest
	MaxHTML          = htmlrender.MaxHTML
	MaxMarkdown      = htmlrender.MaxMarkdown
	MaxResult        = htmlrender.MaxResult
	SnapshotKey      = htmlrender.SnapshotKey
	GenerationPrefix = htmlrender.GenerationPrefix
	shardCount       = htmlrender.ShardCount
	maxShardEntries  = htmlrender.MaxShardEntries
	maxManifest      = htmlrender.MaxManifest
	SnapshotAge      = htmlrender.SnapshotAge
	MaxDomains       = htmlrender.MaxDomains
	MaxSnapshot      = htmlrender.MaxSnapshot
	MaxFeed          = htmlrender.MaxFeed
)

var (
	ErrURL        = htmlrender.ErrURL
	ErrBlocked    = htmlrender.ErrBlocked
	ErrThreats    = htmlrender.ErrThreats
	ErrFetch      = htmlrender.ErrFetch
	ErrSize       = htmlrender.ErrSize
	ErrType       = htmlrender.ErrType
	ErrComplexity = htmlrender.ErrComplexity
)

func CanonicalURL(raw string) (*url.URL, error) { return htmlrender.CanonicalURL(raw) }
func ValidateResult(r Result, input Input, javascript bool) bool {
	return htmlrender.ValidateResult(r, input, javascript)
}
func decodeResult(wire []byte, input Input, javascript bool) (Result, error) {
	return htmlrender.DecodeResult(wire, input, javascript)
}
func Convert(ctx context.Context, source []byte, base *url.URL) (string, string, bool, error) {
	return htmlrender.Convert(ctx, source, base)
}
func DecodeSnapshot(data []byte, now time.Time) (*Snapshot, error) {
	return htmlrender.DecodeSnapshot(data, now)
}
func Refresh(ctx context.Context, transport http.RoundTripper, now time.Time) ([]byte, error) {
	return htmlrender.Refresh(ctx, transport, now)
}
func Code(err error) string                          { return htmlrender.Code(err) }
func shardKey(generation string, prefix byte) string { return htmlrender.ShardKey(generation, prefix) }
