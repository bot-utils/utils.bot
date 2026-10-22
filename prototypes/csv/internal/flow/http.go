package flow

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"utils.bot/csvprototype/internal/tabular"
)

type HTTP struct {
	Engine  *Engine
	Enabled bool
	Logger  *slog.Logger
	slots   chan struct{}
}

func NewHTTP(e *Engine, enabled bool, logger *slog.Logger) *HTTP {
	e.Logger = logger
	return &HTTP{Engine: e, Enabled: enabled, Logger: logger, slots: make(chan struct{}, 4)}
}
func send(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func readJSON(r *http.Request, dst any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return fail(415, "json_required")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, tabular.MaxOptions+1))
	if err != nil || len(raw) > tabular.MaxOptions {
		return fail(413, "request_limit")
	}
	if tabular.StrictJSON(raw, dst) != nil {
		return fail(400, "invalid_request")
	}
	return nil
}
func empty(r *http.Request) error { var body struct{}; return readJSON(r, &body) }
func acceptGzip(v string) bool {
	for _, entry := range strings.Split(v, ",") {
		p := strings.Split(strings.TrimSpace(entry), ";")
		if p[0] != "gzip" {
			continue
		}
		q := 1.0
		for _, attr := range p[1:] {
			a := strings.SplitN(strings.TrimSpace(attr), "=", 2)
			if len(a) != 2 || a[0] != "q" {
				q = 0
				break
			}
			var err error
			q, err = strconv.ParseFloat(a[1], 64)
			if err != nil {
				q = 0
			}
		}
		if q > 0 && q <= 1 {
			return true
		}
	}
	return false
}
func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status, category, route := 500, "service_failure", "unknown"
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Prototype", "local-synthetic-no-funds")
	defer func() {
		if recover() != nil {
			status = 503
			category = "service_failure"
			send(w, 503, map[string]string{"error": "flow_unavailable"})
		}
		if s.Logger != nil {
			s.Logger.Info("csv flow", "route", route, "status", status, "category", category)
		}
	}()
	reject := func(err error) {
		var own *Error
		var tab *tabular.Error
		code := "flow_unavailable"
		status = 503
		if errors.As(err, &own) {
			status, code = own.Status, own.Code
		} else if errors.As(err, &tab) {
			status, code = tab.Status, tab.Code
		}
		category = "service_failure"
		if status < 500 {
			category = "other_4xx"
		}
		if code == "invalid_mock_payment" || code == "payment_owner_mismatch" {
			category = "malformed_proof"
		}
		if code == "payment_unknown" {
			category = "payment_unknown"
		}
		send(w, status, map[string]string{"error": code})
	}
	ok := func(value any) { status = 200; category = "success"; send(w, 200, value) }
	if !s.Enabled {
		reject(fail(404, "not_found"))
		return
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	remote, _, remoteErr := net.SplitHostPort(r.RemoteAddr)
	remoteIP := net.ParseIP(remote)
	if ip == nil || !ip.IsLoopback() || remoteErr != nil || remoteIP == nil || !remoteIP.IsLoopback() || r.Header.Get("Origin") != "" {
		reject(fail(403, "local_client_required"))
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || strings.Contains(r.URL.Path, "//") {
		reject(fail(400, "noncanonical_url"))
		return
	}
	for _, name := range []string{"Content-Type", "Content-Encoding", "X-Job-Capability", "Payment-Signature", "Recovery-Secret", "Idempotency-Key", "X-Upload-Grant", "Download-Attempt", "Range", "If-Range", "If-None-Match", "Accept-Encoding"} {
		if len(r.Header.Values(name)) > 1 {
			reject(fail(400, "duplicate_header"))
			return
		}
	}
	if v := r.Header.Get("Content-Encoding"); v != "" && v != "identity" {
		reject(fail(415, "encoded_input_unsupported"))
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		reject(fail(429, "capacity_unavailable"))
		return
	}
	if err := s.Engine.Sweep(); err != nil {
		reject(err)
		return
	}
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(p) < 2 || p[0] != "csv" {
		reject(fail(404, "not_found"))
		return
	}
	cap := r.Header.Get("X-Job-Capability")
	if r.Method == "POST" && r.URL.Path == "/csv/uploads" {
		route = "upload_admission"
		var intent Intent
		if err := readJSON(r, &intent); err != nil {
			reject(err)
			return
		}
		proof := r.Header.Get("Payment-Signature")
		if proof == "" {
			challenge, err := s.Engine.AdmissionChallenge(intent)
			if err != nil {
				reject(err)
				return
			}
			status = 402
			category = "admission_quote"
			send(w, 402, challenge)
			return
		}
		result, err := s.Engine.Admit(intent, proof, r.Header.Get("Idempotency-Key"), r.Header.Get("Recovery-Secret"))
		if err != nil {
			reject(err)
			return
		}
		ok(result)
		return
	}
	if len(p) == 2 && r.Method == "POST" && (p[1] == "dedupe" || p[1] == "join" || p[1] == "aggregate" || p[1] == "transform") {
		route = "job_submit"
		var request struct {
			JobID string `json:"job_id"`
		}
		if err := readJSON(r, &request); err != nil {
			reject(err)
			return
		}
		result, err := s.Engine.Submit(request.JobID, cap, p[1])
		if err != nil {
			reject(err)
			return
		}
		status = 202
		category = "success"
		w.Header().Set("Retry-After", "1")
		send(w, 202, result)
		return
	}
	if len(p) >= 3 && p[1] == "uploads" {
		id := p[2]
		if len(p) == 6 && p[3] == "parts" && r.Method == "PUT" {
			route = "upload_part"
			n, err := strconv.Atoi(p[5])
			if err != nil || n < 1 || n > 2 || r.Header.Get("Content-Type") != "application/octet-stream" {
				reject(fail(400, "invalid_part"))
				return
			}
			if r.ContentLength > tabular.MaxFile {
				reject(fail(413, "request_limit"))
				return
			}
			data, err := io.ReadAll(io.LimitReader(r.Body, tabular.MaxFile+1))
			if err != nil || len(data) > tabular.MaxFile {
				reject(fail(413, "request_limit"))
				return
			}
			if err = s.Engine.Upload(id, p[4], n, r.Header.Get("X-Upload-Grant"), data); err != nil {
				reject(err)
				return
			}
			ok(map[string]string{"status": "stored"})
			return
		}
		if len(p) == 4 && r.Method == "POST" {
			if err := empty(r); err != nil {
				reject(err)
				return
			}
			switch p[3] {
			case "finalize":
				route = "upload_finalize"
				result, err := s.Engine.Finalize(id, cap)
				if err != nil {
					reject(err)
					return
				}
				ok(result)
				return
			case "grants":
				route = "upload_grants"
				result, err := s.Engine.Renew(id, cap)
				if err != nil {
					reject(err)
					return
				}
				ok(result)
				return
			}
		}
	}
	if len(p) >= 3 && p[1] == "jobs" {
		id := p[2]
		if len(p) == 3 && r.Method == "GET" {
			route = "job_status"
			result, err := s.Engine.Status(id, cap)
			if err != nil {
				reject(err)
				return
			}
			w.Header().Set("Retry-After", "1")
			ok(result)
			return
		}
		if len(p) == 3 && r.Method == "DELETE" {
			route = "job_cancel"
			if err := s.Engine.Cancel(id, cap); err != nil {
				reject(err)
				return
			}
			result, err := s.Engine.Status(id, cap)
			if err != nil {
				reject(err)
				return
			}
			ok(result)
			return
		}
		if len(p) == 4 && r.Method == "POST" {
			switch p[3] {
			case "payment":
				route = "job_payment"
				if err := empty(r); err != nil {
					reject(err)
					return
				}
				proof := r.Header.Get("Payment-Signature")
				if proof == "" {
					if existing, err := s.Engine.Status(id, cap); err == nil && existing.Financial == "PAID" {
						category = "confirmed_paid"
						status = 200
						send(w, 200, existing)
						return
					}
					challenge, err := s.Engine.PaymentChallenge(id, cap)
					if err != nil {
						reject(err)
						return
					}
					status = 402
					category = "result_challenge"
					send(w, 402, challenge)
					return
				}
				result, err := s.Engine.Pay(r.Context(), id, cap, proof)
				if err != nil {
					reject(err)
					return
				}
				status = 200
				category = "provider_attempt"
				if result.Financial == "PAYMENT_UNKNOWN" {
					status = 202
					category = "payment_unknown"
				} else if result.Financial == "PAID" {
					category = "confirmed_paid"
				} else if result.Code == "payment_rejected" {
					status = 402
					category = "definitive_rejection"
				}
				send(w, status, result)
				return
			case "reconcile":
				route = "payment_reconcile"
				if err := empty(r); err != nil {
					reject(err)
					return
				}
				result, err := s.Engine.Reconcile(r.Context(), id, cap)
				if err != nil {
					reject(err)
					return
				}
				ok(result)
				return
			case "ack":
				route = "result_ack"
				var request struct {
					Complete bool   `json:"complete"`
					Version  string `json:"version"`
					SHA256   string `json:"encoded_sha256"`
				}
				if err := readJSON(r, &request); err != nil {
					reject(err)
					return
				}
				if !request.Complete {
					reject(fail(400, "complete_receipt_required"))
					return
				}
				if err := s.Engine.Acknowledge(id, cap, request.Version, request.SHA256); err != nil {
					reject(err)
					return
				}
				ok(map[string]string{"status": "acknowledged"})
				return
			}
		}
		if len(p) == 4 && (p[3] == "result" || p[3] == "result.gz") && (r.Method == "GET" || r.Method == "HEAD") {
			route = "result_download"
			manifest, err := s.Engine.InspectResult(id, cap)
			if err != nil {
				reject(err)
				return
			}
			gzipFile := p[3] == "result.gz"
			if !gzipFile && (!acceptGzip(r.Header.Get("Accept-Encoding")) || r.Header.Get("Range") != "") {
				reject(fail(406, "gzip_or_resumable_route_required"))
				return
			}
			etag := `"` + manifest.Version + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				status = 304
				category = "success"
				w.WriteHeader(304)
				return
			}
			if gzipFile {
				w.Header().Set("Content-Type", "application/gzip")
				w.Header().Set("Content-Disposition", `attachment; filename="result.csv.gz"`)
				w.Header().Set("Accept-Ranges", "bytes")
			} else {
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Vary", "Accept-Encoding")
			}
			w.Header().Set("Content-Length", strconv.Itoa(manifest.EncodedBytes))
			if r.Method == "HEAD" {
				status = 200
				category = "success"
				w.WriteHeader(200)
				return
			}
			rangeHeader := r.Header.Get("Range")
			if tag := r.Header.Get("If-Range"); tag != "" && tag != etag {
				rangeHeader = ""
			}
			dl, err := s.Engine.BeginDownload(id, cap, r.Header.Get("Download-Attempt"), rangeHeader)
			if err != nil {
				w.Header().Del("Content-Length")
				w.Header().Del("Content-Encoding")
				if own, ok := err.(*Error); ok && own.Status == 416 {
					w.Header().Set("Content-Range", "bytes */"+strconv.Itoa(manifest.EncodedBytes))
				}
				reject(err)
				return
			}
			defer s.Engine.EndDownload(id, dl.Lease)
			w.Header().Set("Content-Length", strconv.Itoa(len(dl.Data)))
			status = 200
			category = "success"
			if dl.Partial {
				status = 206
				w.Header().Set("Content-Range", "bytes "+strconv.Itoa(dl.Start)+"-"+strconv.Itoa(dl.End)+"/"+strconv.Itoa(manifest.EncodedBytes))
			}
			w.WriteHeader(status)
			for offset := 0; offset < len(dl.Data); offset += 64 << 10 {
				if r.Context().Err() != nil || !s.Engine.DownloadAllowed(id, dl.Lease) {
					return
				}
				if _, err = w.Write(dl.Data[offset:min(offset+(64<<10), len(dl.Data))]); err != nil {
					return
				}
			}
			return
		}
	}
	reject(fail(404, "not_found"))
}
func (e *Engine) Acknowledge(id, cap, version, sha string) error {
	return e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Financial != "PAID" || j.Manifest == nil || j.Manifest.Version != version || !same(j.Manifest.EncodedSHA256, sha) {
			return fail(409, "receipt_mismatch")
		}
		j.deleting()
		return nil
	})
}
