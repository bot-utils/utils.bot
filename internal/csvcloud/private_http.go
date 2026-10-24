package csvcloud

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	tabular "pdfservice/internal/csvtabular"
	"pdfservice/internal/csvwire"
	"pdfservice/internal/jsonwire"
)

// PrivateHTTP is an unregistered, synthetic-only gateway. The caller supplies
// client-IP evidence from the protected ingress, never a viewer-controlled
// forwarding header. It is not attached to the public server by this package.
type PrivateHTTP struct {
	Enabled, SyntheticOnly bool
	AllowedIP              netip.Addr
	KeySHA256              string
	ClientIP               func(*http.Request) (netip.Addr, error)
	Backend                PrivateHTTPBackend
}
type PrivateHTTPBackend interface {
	Begin(context.Context, csvwire.Request) (PrivateAdmission, error)
	Complete(context.Context, string) error
	Status(context.Context, string) (PrivateStatus, error)
	SimulatePayment(context.Context, string) error
	Download(context.Context, string) (PrivateDownload, error)
	Cancel(context.Context, string) error
}
type PrivatePart struct {
	Slot    string              `json:"slot"`
	Number  int32               `json:"number"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
}

func (PrivatePart) String() string   { return "Private CSV upload grant [redacted]" }
func (PrivatePart) GoString() string { return "Private CSV upload grant [redacted]" }

type PrivateAdmission struct {
	JobID       string        `json:"job_id"`
	Expires     int64         `json:"expires_at"`
	Parts       []PrivatePart `json:"parts"`
	PaymentMode string        `json:"payment_mode"`
}
type PrivateStatus struct {
	JobID        string `json:"job_id"`
	State        string `json:"state"`
	Financial    string `json:"financial_state"`
	Rows         int64  `json:"rows,omitempty"`
	EncodedBytes int64  `json:"compressed_bytes,omitempty"`
	LogicalBytes int64  `json:"logical_bytes,omitempty"`
	PaymentMode  string `json:"payment_mode"`
}

// The backend must establish both callbacks before acquiring a download lease.
// Finish must durably record or preserve reconciliation evidence on failure:
// by then the HTTP body has been sent and an error cannot be reported in JSON.
type PrivateDownload struct {
	Body   io.ReadCloser
	Bytes  int64
	SHA256 string
	// Finish records a complete write to the HTTP transport, not a client
	// receipt. Abort releases the lease without recording completion or
	// refunding the reserved transfer budget. Both must be idempotent.
	Finish func(context.Context) error
	Abort  func(context.Context) error
}

var ErrPrivateUnpaid = errors.New("csv_private_result_unpaid")

func privateJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func privateError(w http.ResponseWriter, err error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(err, ErrPrivateUnpaid):
		status, code = 402, "result_unpaid"
	case errors.Is(err, ErrInvalid):
		status, code = 400, "invalid_request"
	case errors.Is(err, ErrConflict):
		status, code = 409, "state_conflict"
	case errors.Is(err, ErrDisabled):
		status, code = 404, "not_found"
	default:
		var t *tabular.Error
		if errors.As(err, &t) {
			status, code = t.Status, t.Code
		}
	}
	if status >= 500 {
		slog.Warn("private_csv_response", "status", status, "stage", "response", "class", privateFailureClass(err))
	}
	privateJSON(w, status, map[string]string{"error": code})
}
func privateBody(r *http.Request, dst any) error {
	if r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) > 1 || (r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity") {
		return ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, csvwire.MaxHeader+1))
	if err != nil || len(raw) > csvwire.MaxHeader || jsonwire.Decode(raw, dst, csvwire.MaxHeader) != nil {
		return ErrInvalid
	}
	return nil
}
func (s PrivateHTTP) authorized(r *http.Request) bool {
	if !s.Enabled || !s.SyntheticOnly || s.Backend == nil || s.ClientIP == nil || !s.AllowedIP.IsValid() || !opaque(s.KeySHA256) || len(r.Header.Values("X-CSV-Test-Key")) != 1 {
		return false
	}
	ip, err := s.ClientIP(r)
	if err != nil || ip.Unmap() != s.AllowedIP.Unmap() {
		return false
	}
	key := r.Header.Get("X-CSV-Test-Key")
	if !opaque(key) {
		return false
	}
	got := sha256.Sum256([]byte(key))
	want, _ := hex.DecodeString(s.KeySHA256)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
func (s PrivateHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !s.Enabled || !s.SyntheticOnly {
		privateError(w, ErrDisabled)
		return
	}
	if !s.authorized(r) {
		privateJSON(w, 403, map[string]string{"error": "forbidden"})
		return
	}
	w.Header().Set("X-CSV-Payment-Mode", "synthetic-no-funds")
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || strings.Contains(r.URL.Path, "//") || r.Header.Get("Origin") != "" || len(r.Header.Values("Range")) != 0 || len(r.Header.Values("If-Range")) != 0 || r.Method != http.MethodPost && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) || len(r.Header.Values("Payment-Signature")) != 0 {
		privateError(w, ErrInvalid)
		return
	}
	if r.Method == http.MethodPost {
		op := strings.TrimPrefix(r.URL.Path, "/csv/")
		if op == "dedupe" || op == "join" || op == "aggregate" || op == "transform" {
			var body struct {
				Options  json.RawMessage `json:"options"`
				Files    []csvwire.File  `json:"files"`
				Delivery string          `json:"delivery"`
			}
			if privateBody(r, &body) != nil || body.Delivery != "gzip" {
				privateError(w, ErrInvalid)
				return
			}
			options, err := tabular.CanonicalOptions(op, body.Options)
			if err != nil {
				privateError(w, err)
				return
			}
			version := 1
			if op == "transform" && len(body.Files) == 1 && body.Files[0].Bytes > csvwire.MaxInput {
				version = 2
			}
			q := csvwire.Request{Version: version, Operation: op, Options: options, Files: body.Files}
			if q.Validate() != nil {
				privateError(w, ErrInvalid)
				return
			}
			admission, err := s.Backend.Begin(r.Context(), q)
			if err != nil {
				privateError(w, err)
				return
			}
			admission.PaymentMode = "synthetic-no-funds"
			privateJSON(w, 201, admission)
			return
		}
	}
	segments := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(segments) < 3 || len(segments) > 5 || segments[0] != "csv" || segments[1] != "jobs" || !opaque(segments[2]) {
		privateError(w, ErrDisabled)
		return
	}
	id := segments[2]
	if r.Method == http.MethodGet && len(segments) == 3 {
		status, err := s.Backend.Status(r.Context(), id)
		if err != nil {
			privateError(w, err)
			return
		}
		status.PaymentMode = "synthetic-no-funds"
		privateJSON(w, 200, status)
		return
	}
	if r.Method == http.MethodGet && len(segments) == 4 && segments[3] == "download" {
		result, err := s.Backend.Download(r.Context(), id)
		if err != nil {
			privateError(w, err)
			return
		}
		completed, closed := false, false
		defer func() {
			if result.Body != nil && !closed {
				_ = result.Body.Close()
			}
			if !completed && result.Abort != nil {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
				defer cancel()
				_ = result.Abort(cleanup)
			}
		}()
		if result.Body == nil || result.Bytes <= 0 || result.Bytes > MaxResult || !opaque(result.SHA256) || result.Finish == nil || result.Abort == nil {
			privateError(w, ErrUnknown)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", strconv.FormatInt(result.Bytes, 10))
		w.Header().Set("Content-Disposition", `attachment; filename="result.csv.gz"`)
		// The independent manifest already commits to these exact compressed bytes.
		w.Header().Set("ETag", `"`+result.SHA256+`"`)
		w.WriteHeader(http.StatusOK)
		// CopyN can hide an error returned alongside the final requested
		// bytes. Copy a limited reader and check both count and error instead.
		written, copyErr := io.Copy(w, io.LimitReader(result.Body, result.Bytes))
		closeErr := result.Body.Close()
		closed = true
		if copyErr != nil || written != result.Bytes || closeErr != nil || r.Context().Err() != nil {
			return
		}
		finish, done := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer done()
		completed = result.Finish(finish) == nil
		return
	}
	if r.Method != http.MethodPost {
		privateJSON(w, 405, map[string]string{"error": "method_not_allowed"})
		return
	}
	var err error
	switch {
	case len(segments) == 5 && segments[3] == "uploads" && segments[4] == "complete":
		var empty struct{}
		if privateBody(r, &empty) != nil {
			privateError(w, ErrInvalid)
			return
		}
		err = s.Backend.Complete(r.Context(), id)
	case len(segments) == 4 && segments[3] == "payment":
		var body struct {
			Mode string `json:"mode"`
		}
		if privateBody(r, &body) != nil || body.Mode != "synthetic-no-funds" {
			privateError(w, ErrInvalid)
			return
		}
		err = s.Backend.SimulatePayment(r.Context(), id)
	case len(segments) == 4 && segments[3] == "cancel":
		var empty struct{}
		if privateBody(r, &empty) != nil {
			privateError(w, ErrInvalid)
			return
		}
		err = s.Backend.Cancel(r.Context(), id)
	default:
		privateError(w, ErrDisabled)
		return
	}
	if err != nil {
		privateError(w, err)
		return
	}
	privateJSON(w, 202, map[string]string{"job_id": id, "payment_mode": "synthetic-no-funds"})
}
