// Package api exposes a local-only prototype. It has no payment or cloud integration.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"utils.bot/csvprototype/internal/tabular"
)

const MaxRequest = 2*tabular.MaxFile + tabular.MaxOptions + (64 << 10)
const MaxWire = 2 * MaxRequest

type Job struct {
	Operation string            `json:"operation"`
	Options   json.RawMessage   `json:"options"`
	Inputs    map[string][]byte `json:"inputs"`
}
type Reply struct {
	Result *tabular.Result `json:"result,omitempty"`
	Error  *tabular.Error  `json:"error,omitempty"`
}
type Worker func(context.Context, Job) (tabular.Result, error)
type Server struct {
	Work        Worker
	slots       chan struct{}
	Logger      *slog.Logger
	quarantined atomic.Bool
}

func New(work Worker, logger *slog.Logger) *Server {
	return &Server{Work: work, slots: make(chan struct{}, 1), Logger: logger}
}

// ServeHTTP writes no body until processing and serialization both succeed.
// It never calls ParseMultipartForm: customer parts cannot spill to disk.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	operation, code := "unknown", ""
	status := 500
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Prototype", "local-unpaid")
	defer func() {
		if s.Logger != nil {
			s.Logger.Info("csv prototype request", "operation", operation, "status", status, "code", code, "duration_bucket", durationBucket(time.Since(started)))
		}
	}()
	fail := func(err error) {
		e := &tabular.Error{Code: "worker_unavailable", Status: 503}
		var known *tabular.Error
		if errors.As(err, &known) {
			e = known
		}
		status, code = e.Status, e.Code
		respond(w, status, map[string]string{"error": code})
	}
	w.Header().Set("Connection", "close")
	host := r.Host
	if parsed, _, e := net.SplitHostPort(host); e == nil {
		host = parsed
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || r.Header.Get("Origin") != "" {
		fail(&tabular.Error{Code: "local_client_required", Status: 403})
		return
	}
	if r.URL.Path == "/health" && r.Method == "GET" && r.URL.RawQuery == "" && !r.URL.ForceQuery && r.URL.RawPath == "" {
		if s.quarantined.Load() {
			fail(&tabular.Error{Code: "worker_cleanup_failed", Status: 503})
			return
		}
		status = 200
		respond(w, 200, map[string]string{"status": "ready", "mode": "local-unpaid-prototype"})
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		fail(&tabular.Error{Code: "noncanonical_url", Status: 400})
		return
	}
	switch r.URL.Path {
	case "/csv/dedupe":
		operation = "dedupe"
	case "/csv/join":
		operation = "join"
	case "/csv/aggregate":
		operation = "aggregate"
	default:
		fail(&tabular.Error{Code: "not_found", Status: 404})
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(&tabular.Error{Code: "method_not_allowed", Status: 405})
		return
	}
	if len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) > 1 || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		fail(&tabular.Error{Code: "unsupported_media_type", Status: 415})
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "multipart/form-data" {
		fail(&tabular.Error{Code: "multipart_required", Status: 415})
		return
	}
	if r.ContentLength > MaxRequest {
		fail(&tabular.Error{Code: "request_limit", Status: 413})
		return
	}
	if s.quarantined.Load() {
		fail(&tabular.Error{Code: "worker_cleanup_failed", Status: 503})
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
		if s.quarantined.Load() {
			fail(&tabular.Error{Code: "worker_cleanup_failed", Status: 503})
			return
		}
	default:
		w.Header().Set("Retry-After", "1")
		fail(&tabular.Error{Code: "capacity_unavailable", Status: 429})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequest)
	defer r.Body.Close()
	reader, err := r.MultipartReader()
	if err != nil {
		fail(&tabular.Error{Code: "invalid_multipart", Status: 400})
		return
	}
	job := Job{Operation: operation, Inputs: map[string][]byte{}}
	seen := map[string]bool{}
	expected := map[string]bool{"options": true, "file": true}
	if operation == "join" {
		expected = map[string]bool{"options": true, "left": true, "right": true}
	}
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(partError(err))
			return
		}
		name := part.FormName()
		// Transfer encodings are not part of this contract. NextRawPart avoids
		// implicit decoding too; reject before reading any part content.
		if !expected[name] || seen[name] || len(part.Header.Values("Content-Disposition")) != 1 || len(part.Header.Values("Content-Transfer-Encoding")) != 0 {
			fail(&tabular.Error{Code: "invalid_parts", Status: 400})
			return
		}
		seen[name] = true
		cap := tabular.MaxFile
		if name == "options" {
			cap = tabular.MaxOptions
		}
		data, e := io.ReadAll(io.LimitReader(part, int64(cap)+1))
		if e != nil {
			fail(partError(e))
			return
		}
		if len(data) > cap {
			code := "file_limit"
			if name == "options" {
				code = "options_limit"
			}
			fail(&tabular.Error{Code: code, Status: 413})
			return
		}
		if name == "options" {
			job.Options = data
		} else {
			job.Inputs[name] = data
		}
	}
	if len(seen) != len(expected) {
		fail(&tabular.Error{Code: "invalid_parts", Status: 400})
		return
	}
	// MIME permits epilogue after the closing boundary. Discard it consistently,
	// whether multipart.Reader buffered it or left it on the underlying body.
	// Drain under the same total byte cap before starting any worker.
	if _, e := io.Copy(io.Discard, r.Body); e != nil {
		fail(partError(e))
		return
	}
	if r.Context().Err() != nil {
		fail(&tabular.Error{Code: "request_cancelled", Status: 408})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.Work(ctx, job)
	if err != nil {
		var workerErr *tabular.Error
		if errors.As(err, &workerErr) && workerErr.Code == "worker_cleanup_failed" {
			s.quarantined.Store(true)
		}
		fail(err)
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > tabular.MaxOutput {
		fail(&tabular.Error{Code: "output_byte_limit", Status: 413})
		return
	}
	status = 200
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(encoded)
}
func partError(err error) error {
	var large *http.MaxBytesError
	if errors.As(err, &large) {
		return &tabular.Error{Code: "request_limit", Status: 413}
	}
	return &tabular.Error{Code: "invalid_multipart", Status: 400}
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func durationBucket(d time.Duration) string {
	switch {
	case d < time.Second:
		return "under_1s"
	case d < 5*time.Second:
		return "1_to_5s"
	case d < 15*time.Second:
		return "5_to_15s"
	default:
		return "15s_or_more"
	}
}
