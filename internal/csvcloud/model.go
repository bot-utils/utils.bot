// Package csvcloud contains unlaunched CSV adapters. Nothing in this package is
// registered with the public service. Dispatch and settlement default to off.
package csvcloud

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"pdfservice/internal/protocol"
	"reflect"
	"strings"
	"sync/atomic"
)

var ErrDisabled = errors.New("csv_adapter_disabled")
var ErrConflict = errors.New("csv_state_conflict")
var ErrUnknown = errors.New("csv_outcome_unknown")
var ErrIntegrity = errors.New("csv_integrity_failed")
var ErrCleanup = errors.New("csv_cleanup_unconfirmed")
var ErrInvalid = errors.New("csv_invalid_metadata")

const Region = "us-east-2"
const MaxInput int64 = 1 << 30
const MaxResult int64 = 1 << 30
const MaxMetadata = 64 << 10

type Gate struct{ Enabled, Dispatch, Settlement bool }

func ID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("entropy_unavailable")
	}
	return hex.EncodeToString(b[:])
}
func Hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func opaque(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}

type Object struct {
	JobID, ID, Slot, ETag, SHA256 string
	Bytes                         int64
}

func (o Object) key(result bool) string {
	if result {
		return "results/" + o.JobID + "/" + o.ID
	}
	return "inputs/" + o.JobID + "/" + o.ID
}
func (o Object) valid() bool {
	return opaque(o.JobID) && opaque(o.ID) && (o.Slot == "file" || o.Slot == "left" || o.Slot == "right" || o.Slot == "result") && opaque(o.SHA256) && o.Bytes > 0 && o.Bytes <= MaxInput
}

type Manifest struct {
	Object        Object
	LogicalBytes  int64
	LogicalSHA256 string
	Rows          int64
}

func (m Manifest) Valid() bool {
	return m.Object.valid() && m.Object.Slot == "result" && m.Object.ETag != "" && m.Object.Bytes <= MaxResult && m.LogicalBytes > 0 && m.LogicalBytes <= MaxResult && opaque(m.LogicalSHA256) && m.Rows >= 0 && m.Rows <= 10_000_000
}

type Dispatch struct {
	Token, Parameters, TaskARN, State string
	ReservedMicroUSD, Started         int64
}
type Settlement struct {
	StartBlock                                                             int64
	ID, Nonce, Payer, Receiver, Asset, Network, Amount, State, Transaction string
	ValidBefore, Started, UnknownAt                                        int64
}
type Job struct {
	QuoteCount                                                                                          int
	DownloadStart, DownloadEnd                                                                          int64
	DownloadClaimed                                                                                     bool
	Quote                                                                                               *Quote
	ID, IntentBinding, Owner, AdmissionNonceHash, IdempotencyHash, RecoveryVerifier, CapabilityVerifier string
	Version                                                                                             int64
	Artifact, Financial                                                                                 string
	UploadUntil, ResultUntil                                                                            int64
	Inputs                                                                                              []Object
	Result                                                                                              *Manifest
	Dispatch                                                                                            *Dispatch
	Settlement                                                                                          *Settlement
	DownloadUsed                                                                                        int64
	DownloadLease                                                                                       string
	DownloadUntil                                                                                       int64
	Remedy                                                                                              bool
}

func (j Job) valid() bool {
	if j.Settlement != nil && !j.Settlement.valid(j.Financial) {
		return false
	}
	if (j.Financial == "SETTLEMENT_PENDING" || j.Financial == "PAYMENT_UNKNOWN" || j.Financial == "PAID") && j.Settlement == nil {
		return false
	}
	if j.Artifact == "ERASED" {
		minimal := Job{ID: j.ID, Version: j.Version, Artifact: j.Artifact, Financial: j.Financial, RecoveryVerifier: j.RecoveryVerifier, Settlement: j.Settlement, Remedy: j.Remedy}
		return reflect.DeepEqual(j, minimal) && opaque(j.ID) && j.Version >= 1 && opaque(j.RecoveryVerifier) && (j.Financial == "UNPAID" || j.Financial == "PAYMENT_UNKNOWN" || j.Financial == "PAID")
	}

	if !opaque(j.ID) || !opaque(j.IntentBinding) || !opaque(j.AdmissionNonceHash) || !opaque(j.IdempotencyHash) || !opaque(j.RecoveryVerifier) || !opaque(j.CapabilityVerifier) || j.Version < 1 {
		return false
	}
	if !protocol.Hex(j.Owner, 20) || j.QuoteCount < 0 || j.QuoteCount > 3 || j.DownloadUsed < 0 || j.UploadUntil <= 0 {
		return false
	}
	switch j.Artifact {
	case "UPLOAD_INCOMPLETE", "UPLOAD_VERIFIED", "QUEUED", "DISPATCH_RESERVED", "RUNNING", "PROCESSING_UNKNOWN", "RESULT_PREPARED", "QUARANTINED", "RETRIEVABLE", "DELETING", "ERASED":
	default:
		return false
	}
	switch j.Financial {
	case "UNPAID", "AWAITING_PAYMENT", "SETTLEMENT_PENDING", "PAYMENT_UNKNOWN", "PAID":
	default:
		return false
	}
	if len(j.Inputs) < 1 || len(j.Inputs) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, o := range j.Inputs {
		if !o.valid() || o.JobID != j.ID || o.Slot == "result" || seen[o.Slot] {
			return false
		}
		if j.Artifact != "UPLOAD_INCOMPLETE" && j.Artifact != "DELETING" && o.ETag == "" {
			return false
		}
		seen[o.Slot] = true
	}
	if len(j.Inputs) == 2 && (!seen["left"] || !seen["right"]) {
		return false
	}
	if j.Result != nil && (!j.Result.Valid() || j.Result.Object.JobID != j.ID) {
		return false
	}
	if (j.Artifact == "RESULT_PREPARED" || j.Artifact == "RETRIEVABLE" || j.Artifact == "QUARANTINED") && j.Result == nil {
		return false
	}
	if j.Artifact == "RETRIEVABLE" && j.Financial != "PAID" || j.Artifact == "QUARANTINED" && j.Financial != "PAYMENT_UNKNOWN" {
		return false
	}
	switch j.Artifact {
	case "QUEUED":
		if j.Dispatch == nil || j.Dispatch.State != "RESERVED" || j.Dispatch.Parameters != "" || j.Dispatch.Started != 0 || j.Dispatch.TaskARN != "" {
			return false
		}
	case "DISPATCH_RESERVED":
		if j.Dispatch == nil || j.Dispatch.State != "STARTING" || !opaque(j.Dispatch.Parameters) || j.Dispatch.Started <= 0 || j.Dispatch.TaskARN != "" {
			return false
		}
	case "RUNNING", "RESULT_PREPARED", "QUARANTINED", "RETRIEVABLE":
		if j.Dispatch == nil || j.Dispatch.State != "ACTIVE" || !opaque(j.Dispatch.Parameters) || j.Dispatch.Started <= 0 || j.Dispatch.TaskARN == "" {
			return false
		}
	case "PROCESSING_UNKNOWN":
		if j.Dispatch == nil || j.Dispatch.State != "STOPPED_UNVERIFIED" || !opaque(j.Dispatch.Parameters) || j.Dispatch.Started <= 0 || j.Dispatch.TaskARN == "" {
			return false
		}
	}
	if j.Artifact == "RESULT_PREPARED" && j.Financial != "AWAITING_PAYMENT" && j.Financial != "SETTLEMENT_PENDING" {
		return false
	}
	if j.Result != nil && j.Artifact != "RESULT_PREPARED" && j.Artifact != "QUARANTINED" && j.Artifact != "RETRIEVABLE" && j.Artifact != "DELETING" {
		return false
	}
	if j.Dispatch != nil && (!opaque(j.Dispatch.Token) || j.Dispatch.ReservedMicroUSD <= 0 || j.Dispatch.Parameters != "" && !opaque(j.Dispatch.Parameters) || len(j.Dispatch.TaskARN) > 256) {
		return false
	}
	if j.Settlement != nil && !strings.EqualFold(j.Settlement.Payer, j.Owner) {
		return false
	}

	raw, e := json.Marshal(j)
	return e == nil && len(raw) <= MaxMetadata && len(j.Inputs) <= 2
}
func sameJob(a, b Job) bool {
	return a.ID == b.ID && a.IntentBinding == b.IntentBinding && strings.EqualFold(a.Owner, b.Owner) && a.AdmissionNonceHash == b.AdmissionNonceHash && a.IdempotencyHash == b.IdempotencyHash && a.RecoveryVerifier == b.RecoveryVerifier && a.CapabilityVerifier == b.CapabilityVerifier
}

type DownloadPermit struct {
	job  Job
	used atomic.Bool
}

// validReplacement preserves identities after their one durable reservation.
func validReplacement(a, b Job) bool {
	if a.Remedy && !b.Remedy || !a.valid() || !b.valid() || !sameJob(a, b) || b.Version != a.Version+1 || b.DownloadUsed < a.DownloadUsed || b.QuoteCount < a.QuoteCount {
		return false
	}
	allowed := map[string]map[string]bool{"UNPAID": {"UNPAID": true, "AWAITING_PAYMENT": true}, "AWAITING_PAYMENT": {"AWAITING_PAYMENT": true, "SETTLEMENT_PENDING": true}, "SETTLEMENT_PENDING": {"SETTLEMENT_PENDING": true, "PAYMENT_UNKNOWN": true}, "PAYMENT_UNKNOWN": {"PAYMENT_UNKNOWN": true, "PAID": true, "UNPAID": true}, "PAID": {"PAID": true}}
	if !allowed[a.Financial][b.Financial] {
		return false
	}
	artifactAllowed := map[string]map[string]bool{
		"UPLOAD_INCOMPLETE":  {"UPLOAD_INCOMPLETE": true, "UPLOAD_VERIFIED": true, "DELETING": true},
		"UPLOAD_VERIFIED":    {"UPLOAD_VERIFIED": true, "QUEUED": true, "DELETING": true},
		"QUEUED":             {"QUEUED": true, "DISPATCH_RESERVED": true, "DELETING": true},
		"DISPATCH_RESERVED":  {"DISPATCH_RESERVED": true, "RUNNING": true, "PROCESSING_UNKNOWN": true, "DELETING": true},
		"RUNNING":            {"RUNNING": true, "RESULT_PREPARED": true, "PROCESSING_UNKNOWN": true, "DELETING": true},
		"PROCESSING_UNKNOWN": {"PROCESSING_UNKNOWN": true, "DELETING": true},
		"RESULT_PREPARED":    {"RESULT_PREPARED": true, "QUARANTINED": true, "DELETING": true},
		"QUARANTINED":        {"QUARANTINED": true, "RETRIEVABLE": true, "DELETING": true},
		"RETRIEVABLE":        {"RETRIEVABLE": true, "DELETING": true},
		"DELETING":           {"DELETING": true, "ERASED": true}, "ERASED": {"ERASED": true},
	}
	if !artifactAllowed[a.Artifact][b.Artifact] {
		return false
	}
	if !reflect.DeepEqual(a.Inputs, b.Inputs) {
		if a.Artifact != "UPLOAD_INCOMPLETE" || b.Artifact != "UPLOAD_VERIFIED" || len(a.Inputs) != len(b.Inputs) || len(a.Inputs) == 0 {
			return false
		}
		for i, x := range a.Inputs {
			y := b.Inputs[i]
			if x.ETag != "" && x.ETag != y.ETag || y.ETag == "" {
				return false
			}
			x.ETag = ""
			y.ETag = ""
			if x != y {
				return false
			}
		}
	}
	if a.Result != nil && !reflect.DeepEqual(a.Result, b.Result) {
		return false
	}
	if a.Settlement != nil {
		if b.Settlement == nil {
			return false
		}
		x, y := *a.Settlement, *b.Settlement
		x.State = ""
		y.State = ""
		x.Transaction = ""
		y.Transaction = ""
		x.UnknownAt = 0
		y.UnknownAt = 0
		if x != y || a.Settlement.Transaction != "" && a.Settlement.Transaction != b.Settlement.Transaction {
			return false
		}
	}
	if a.Dispatch != nil {
		if b.Dispatch == nil || a.Dispatch.Token != b.Dispatch.Token || a.Dispatch.ReservedMicroUSD != b.Dispatch.ReservedMicroUSD || a.Dispatch.Parameters != "" && a.Dispatch.Parameters != b.Dispatch.Parameters || a.Dispatch.Started != 0 && a.Dispatch.Started != b.Dispatch.Started || a.Dispatch.TaskARN != "" && a.Dispatch.TaskARN != b.Dispatch.TaskARN {
			return false
		}
	}
	if a.Artifact == "ERASED" && b.Artifact != "ERASED" || a.Artifact == "DELETING" && b.Artifact != "DELETING" && b.Artifact != "ERASED" {
		return false
	}
	if a.Financial == "PAID" && b.Financial != "PAID" || a.Financial == "PAYMENT_UNKNOWN" && b.Financial != "PAYMENT_UNKNOWN" && b.Financial != "PAID" && b.Financial != "UNPAID" {
		return false
	}
	return true
}

func (x Settlement) valid(financial string) bool {
	switch x.State {
	case "SETTLEMENT_PENDING", "PAYMENT_UNKNOWN", "PAID", "UNPAID":
	default:
		return false
	}
	return (x.State != "PAID" || protocol.Hex(x.Transaction, 32)) && x.State == financial && opaque(x.ID) && protocol.Hex(x.Nonce, 32) && protocol.Hex(x.Payer, 20) && protocol.Hex(x.Receiver, 20) && protocol.Hex(x.Asset, 20) && (x.Network == "eip155:8453" || x.Network == "eip155:84532") && x.StartBlock >= 0 && x.Started > 0 && x.ValidBefore > x.Started && x.UnknownAt >= 0 && validAmount(x.Amount) && (x.Transaction == "" || protocol.Hex(x.Transaction, 32))
}
