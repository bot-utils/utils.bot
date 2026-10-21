package htmlrender

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"pdfservice/internal/htmllimits"
	"pdfservice/internal/jsonwire"
)

type VMJob struct {
	Input    Input    `json:"input"`
	Manifest []byte   `json:"manifest"`
	Shards   []string `json:"shards"`
}

func ThreatLink(raw, bucket, key string) bool {
	u, e := url.Parse(raw)
	return len(raw) <= 8192 && e == nil && u.Scheme == "https" && u.Host == bucket+".s3.us-east-2.amazonaws.com" && u.User == nil && u.Opaque == "" && u.Fragment == "" && u.Path == "/"+key && u.RawPath == "" && u.Query().Get("X-Amz-Signature") != ""
}

type jobThreatReader struct {
	job    VMJob
	bucket string
	client *http.Client
}

func (j jobThreatReader) OpenObject(ctx context.Context, bucket, key string) (io.ReadCloser, *int64, error) {
	if bucket != j.bucket {
		return nil, nil, ErrThreats
	}
	if key == SnapshotKey {
		return io.NopCloser(bytes.NewReader(j.job.Manifest)), nil, nil
	}
	var m Manifest
	if jsonwire.Decode(j.job.Manifest, &m, MaxManifest) != nil {
		return nil, nil, ErrThreats
	}
	prefix := GenerationPrefix + m.Generation + "/"
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, ".bin") || len(j.job.Shards) != ShardCount {
		return nil, nil, ErrThreats
	}
	index, e := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(key, prefix), ".bin"))
	if e != nil || len(index) != 1 {
		return nil, nil, ErrThreats
	}
	raw := j.job.Shards[int(index[0])]
	if !ThreatLink(raw, j.bucket, key) {
		return nil, nil, ErrThreats
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return nil, nil, ErrThreats
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, e := j.client.Do(req)
	if e != nil {
		return nil, nil, ErrThreats
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" {
		resp.Body.Close()
		return nil, nil, ErrThreats
	}
	return resp.Body, &resp.ContentLength, nil
}

// VMServer is deliberately one-shot. Lifecycle hooks cannot reset a consumed
// job. No request/error logger is installed, and only fixed errors are emitted.
type VMServer struct {
	Probe    bool
	Bucket   string
	SelfTest func(context.Context) error
	Validate func(context.Context) error
	Fetch    func(context.Context, string, DomainCheck) (Result, error)
	phase    atomic.Int32
}

const hookPrefix = "/aws/lambda-microvms/runtime/v1/"

func (s *VMServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(status int) { w.WriteHeader(status); io.WriteString(w, `{"error":"conversion_unavailable"}`) }
	defer func() {
		if recover() != nil {
			fail(502)
		}
	}()
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Encoding") != "" {
		fail(400)
		return
	}
	switch r.URL.Path {
	case hookPrefix + "ready", hookPrefix + "validate":
		if s.phase.Load() != 0 || s.SelfTest == nil {
			fail(503)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		check := s.SelfTest
		if r.URL.Path == hookPrefix+"validate" && s.Validate != nil {
			check = s.Validate
		}
		if check(ctx) != nil {
			fail(503)
			return
		}
		io.WriteString(w, `{}`)
		return
	case "/convert":
	default:
		fail(404)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" || !s.phase.CompareAndSwap(0, 2) {
		fail(409)
		return
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, htmllimits.VMMaxJob+1))
	if s.Probe {
		check := s.Validate
		if check == nil {
			check = s.SelfTest
		}
		if e != nil || !bytes.Equal(bytes.TrimSpace(body), []byte("{}")) || check == nil {
			fail(400)
			return
		}
		started := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if check(ctx) != nil {
			fail(503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "elapsedMS": time.Since(started).Milliseconds()})
		return
	}
	var job VMJob
	if e != nil || jsonwire.Decode(body, &job, htmllimits.VMMaxJob) != nil || len(job.Shards) != ShardCount {
		fail(400)
		return
	}
	if _, e = CanonicalURL(job.Input.URL); e != nil {
		fail(400)
		return
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	worker := Worker{Load: func(ctx context.Context) (DomainCheck, error) {
		return LoadSnapshot(ctx, jobThreatReader{job: job, bucket: s.Bucket, client: client}, s.Bucket, time.Now())
	}, Fetch: s.Fetch}
	payload, _ := json.Marshal(job.Input)
	result, _ := worker.Invoke(r.Context(), payload)
	if _, err := DecodeResult(result, job.Input, true); err != nil {
		fail(502)
		return
	}
	w.Write(result)
}
