package htmlrender

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const SnapshotAge = 24 * time.Hour
const MaxDomains = 4_000_000
const MaxSnapshot = 56 + 32*MaxDomains
const MaxFeed = 128 << 20

// These are fixed publisher URLs, never supplied by customers. Data provenance
// and reuse terms are recorded in THIRD_PARTY.md.
var feedSources = []struct {
	URL    string
	Min    int
	Hagezi bool
}{
	{"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt", 1_000_000, true},
	{"https://hole.cert.pl/domains/v2/domains.txt", 10_000, false},
}

type Snapshot struct {
	data      []byte
	refreshed time.Time
}

// A compact sorted SHA-256 index avoids millions of Go map/string allocations.
// The digest detects corruption; authenticity comes from TLS and private S3 IAM.
func DecodeSnapshot(b []byte, now time.Time) (*Snapshot, error) {
	if len(b) < 56 || len(b) > MaxSnapshot || string(b[:8]) != "UBTHRT01" {
		return nil, ErrThreats
	}
	stamp := int64(binary.BigEndian.Uint64(b[8:16]))
	count := binary.BigEndian.Uint64(b[16:24])
	if count == 0 || count > MaxDomains || uint64(len(b)-56) != 32*count {
		return nil, ErrThreats
	}
	digest := sha256.Sum256(b[56:])
	if !bytes.Equal(digest[:], b[24:56]) {
		return nil, ErrThreats
	}
	s := &Snapshot{data: b[56:], refreshed: time.Unix(stamp, 0)}
	if s.fresh(now) != nil {
		return nil, ErrThreats
	}
	for i := 32; i < len(s.data); i += 32 {
		if bytes.Compare(s.data[i-32:i], s.data[i:i+32]) >= 0 {
			return nil, ErrThreats
		}
	}
	return s, nil
}
func (s *Snapshot) fresh(now time.Time) error {
	if s == nil || now.Sub(s.refreshed) > SnapshotAge || s.refreshed.After(now.Add(5*time.Minute)) {
		return ErrThreats
	}
	return nil
}
func (s *Snapshot) Check(ctx context.Context, host string, now time.Time) error {
	if ctx.Err() != nil {
		return ErrThreats
	}
	if err := s.fresh(now); err != nil {
		return err
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !domainName(host) {
		return ErrBlocked
	}
	for strings.Contains(host, ".") {
		digest := sha256.Sum256([]byte(host))
		if containsHash(s.data, digest) {
			return ErrBlocked
		}
		host = host[strings.IndexByte(host, '.')+1:]
	}
	return nil
}

func containsHash(data []byte, digest [32]byte) bool {
	lo, hi := 0, len(data)/32
	for lo < hi {
		mid := (lo + hi) / 2
		if bytes.Compare(data[mid*32:(mid+1)*32], digest[:]) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < len(data)/32 && bytes.Equal(data[lo*32:(lo+1)*32], digest[:])
}

func EncodeSnapshot(hashes [][32]byte, now time.Time) ([]byte, error) {
	if len(hashes) == 0 || len(hashes) > MaxDomains {
		return nil, ErrThreats
	}
	slices.SortFunc(hashes, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	hashes = slices.Compact(hashes)
	data := make([]byte, 56+len(hashes)*32)
	copy(data, "UBTHRT01")
	binary.BigEndian.PutUint64(data[8:16], uint64(now.Unix()))
	binary.BigEndian.PutUint64(data[16:24], uint64(len(hashes)))
	for i, h := range hashes {
		copy(data[56+i*32:], h[:])
	}
	digest := sha256.Sum256(data[56:])
	copy(data[24:56], digest[:])
	return data, nil
}

func parseFeed(r io.Reader, min int, hagezi bool, modified time.Time, now time.Time, hashes *[][32]byte) error {
	limited := &io.LimitedReader{R: r, N: MaxFeed + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 4096)
	count, declared := 0, 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# Number of entries:") && hagezi {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "# Number of entries:")))
			if err != nil || n <= 0 || n > MaxDomains {
				return ErrThreats
			}
			declared = n
		}
		if strings.HasPrefix(line, "# Last modified:") && hagezi {
			parsed, err := time.Parse("2 Jan 2006 15:04 MST", strings.TrimSpace(strings.TrimPrefix(line, "# Last modified:")))
			if err != nil {
				return ErrThreats
			}
			modified = parsed
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := strings.ToLower(strings.TrimSuffix(line, "."))
		if !domainName(domain) || len(*hashes) >= MaxDomains {
			return ErrThreats
		}
		*hashes = append(*hashes, sha256.Sum256([]byte(domain)))
		count++
	}
	// A stale upstream file cannot be made fresh just by fetching it again.
	if scanner.Err() != nil || limited.N <= 0 || count < min || hagezi && count != declared || modified.IsZero() || now.Sub(modified) > 72*time.Hour || modified.After(now.Add(5*time.Minute)) {
		return ErrThreats
	}
	return nil
}

// Refresh downloads both complete feeds before replacing any last-good snapshot.
// Failure (including partial/truncated feeds) leaves the caller's S3 object alone.
func Refresh(ctx context.Context, transport http.RoundTripper, now time.Time) ([]byte, error) {
	if transport == nil {
		t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10}
		defer t.CloseIdleConnections()
		transport = t
	}
	client := &http.Client{Timeout: 90 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	hashes := make([][32]byte, 0, 2_500_000)
	for _, source := range feedSources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
		if err != nil {
			return nil, ErrThreats
		}
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("User-Agent", "utils.bot-threat-refresh/1.0")
		resp, err := client.Do(req)
		if err != nil {
			return nil, ErrThreats
		}
		if resp.StatusCode != 200 || resp.ContentLength > MaxFeed || resp.Header.Get("Content-Encoding") != "" {
			resp.Body.Close()
			return nil, ErrThreats
		}
		modified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
		err = parseFeed(resp.Body, source.Min, source.Hagezi, modified, now, &hashes)
		resp.Body.Close()
		if err != nil {
			return nil, ErrThreats
		}
	}
	return EncodeSnapshot(hashes, now)
}

// Code returns only fixed error categories, never provider diagnostics or URLs.
func Code(err error) string {
	for _, known := range []error{ErrURL, ErrBlocked, ErrThreats, ErrFetch, ErrSize, ErrType, ErrComplexity} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "conversion_unavailable"
}
