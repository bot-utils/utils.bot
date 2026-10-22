package flow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const PartSize = 4 << 20 // Local 8 MiB rehearsal; not the proposed AWS part size.
const maxRecords = 32
const UploadWindow = 30 * time.Minute
const ResultWindow = 30 * time.Minute
const UnknownWindow = 24 * time.Hour

type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string           { return e.Code }
func fail(status int, code string) error { return &Error{status, code} }
func random() string {
	var p [32]byte
	if _, e := rand.Read(p[:]); e != nil {
		panic("entropy_unavailable")
	}
	return hex.EncodeToString(p[:])
}
func digest(p []byte) string { h := sha256.Sum256(p); return hex.EncodeToString(h[:]) }
func keyed(key string, fields ...any) string {
	raw, _ := json.Marshal(fields)
	m := hmac.New(sha256.New, []byte(key))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))
}
func secret(v string) bool {
	p, e := hex.DecodeString(v)
	return e == nil && len(p) == 32 && hex.EncodeToString(p) == v
}
func same(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

type FileSpec struct {
	Slot   string `json:"slot"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
}
type Intent struct {
	Operation string          `json:"operation"`
	Options   json.RawMessage `json:"options"`
	Files     []FileSpec      `json:"files"`
	Delivery  string          `json:"delivery"`
}
type Grant struct {
	Slot    string `json:"slot"`
	Part    int    `json:"part"`
	Bytes   int    `json:"bytes"`
	Path    string `json:"path"`
	Header  string `json:"upload_grant"`
	Expires int64  `json:"expires_at"`
}
type Admission struct {
	JobID      string  `json:"job_id"`
	Capability string  `json:"capability"`
	Expires    int64   `json:"expires_at"`
	Grants     []Grant `json:"grants"`
}
type Manifest struct {
	Version       string `json:"version"`
	Format        string `json:"format"`
	EncodedBytes  int    `json:"encoded_bytes"`
	LogicalBytes  int    `json:"logical_bytes"`
	Rows          int    `json:"rows"`
	EncodedSHA256 string `json:"encoded_sha256"`
	LogicalSHA256 string `json:"logical_sha256"`
}
type Status struct {
	JobID             string    `json:"job_id"`
	Artifact          string    `json:"artifact_state"`
	Financial         string    `json:"financial_state"`
	Expires           int64     `json:"expires_at"`
	Code              string    `json:"code,omitempty"`
	EncodedBytes      int       `json:"encoded_bytes,omitempty"`
	LogicalBytes      int       `json:"logical_bytes,omitempty"`
	DownloadRemaining int       `json:"download_remaining"`
	Remedy            bool      `json:"remedy_required_if_paid"`
	Manifest          *Manifest `json:"manifest,omitempty"`
}
type part struct {
	Bytes  []byte
	SHA256 string
}
type file struct {
	Spec     FileSpec
	Parts    map[int]part
	Complete []byte
}
type download struct {
	Bytes int
	Lease string
	Until int64
}
type reservation struct {
	ID, ProofHash, Binding, Outcome string
	Started                         int64
}
type job struct {
	GrantUntil                                                           int64
	ID, Binding, Owner, Nonce, Idempotency, RecoveryHash, CapabilityHash string
	Intent                                                               Intent
	Artifact, Financial, Code                                            string
	UploadUntil, ResultUntil, UnknownAt                                  int64
	Files                                                                map[string]*file
	Epoch                                                                int
	Token                                                                string
	Cancel                                                               bool
	Quarantined                                                          bool
	UploadBytes, GrantCalls                                              int
	Manifest                                                             *Manifest
	Result                                                               []byte
	Reservation                                                          *reservation
	DownloadUsed                                                         int
	Downloads                                                            map[string]download
	ActiveDownload                                                       string
	Remedy                                                               bool
}
type database struct {
	Schema              int
	Key                 string
	Quarantine          bool
	Jobs                map[string]*job
	Idempotency, Nonces map[string]string
	Provider            map[string]string
	SettlementCalls     int
}

func (j *job) expiry() int64 {
	if j.Financial == "PAYMENT_UNKNOWN" {
		return j.UnknownAt + int64(UnknownWindow/time.Second)
	}
	if j.ResultUntil != 0 {
		return j.ResultUntil
	}
	return j.UploadUntil
}
func (j *job) status() Status {
	s := Status{JobID: j.ID, Artifact: j.Artifact, Financial: j.Financial, Expires: j.expiry(), Code: j.Code, Remedy: j.Remedy}
	if j.Manifest != nil {
		s.EncodedBytes = j.Manifest.EncodedBytes
		s.LogicalBytes = j.Manifest.LogicalBytes
		s.DownloadRemaining = max(0, 3*j.Manifest.EncodedBytes-j.DownloadUsed)
		if j.Financial == "PAID" {
			m := *j.Manifest
			s.Manifest = &m
		}
	}
	return s
}
func (j *job) erase() {
	if j.Financial == "PAYMENT_UNKNOWN" || j.Financial == "SETTLEMENT_PENDING" {
		j.Remedy = true
	}
	j.Files = map[string]*file{}
	j.Result = nil
	j.Artifact = "ERASED"
	j.Epoch++
	j.Token = ""
}
func (j *job) deleting() {
	j.Cancel = true
	j.Epoch++
	j.Artifact = "DELETING"
	if j.Token == "" && j.ActiveDownload == "" {
		j.erase()
	}
}
func auth(d *database, id, capability string) (*job, error) {
	j := d.Jobs[id]
	if j == nil || !secret(capability) || !same(j.CapabilityHash, keyed(d.Key, "cap-verifier-v1", capability)) {
		return nil, fail(404, "not_found")
	}
	return j, nil
}
func (j *job) paymentBinding() string {
	raw, _ := json.Marshal(j.Manifest)
	return digest([]byte(fmt.Sprintf("v1|%s|%s|%s|%s|%s", j.ID, j.Owner, j.Nonce, j.Binding, digest(raw))))
}
