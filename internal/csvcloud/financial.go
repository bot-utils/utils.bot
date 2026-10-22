package csvcloud

import (
	"context"
	"strings"

	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"pdfservice/internal/protocol"
)

// These persistence operations are package-private. Generic Replace cannot
// alter financial state, settlement evidence, or settlement outcome. Each
// operation owns the particular external-evidence boundary it represents.
func (r Repository) publishResult(ctx context.Context, old Job, m Manifest, until int64) (Job, error) {
	if !r.Gate.Enabled {
		return old, ErrDisabled
	}
	if !old.valid() || old.Artifact != "RUNNING" || !old.TransferStarted || !old.WorkerStopped || old.Financial != "UNPAID" || old.Dispatch == nil || old.Dispatch.State != "ACTIVE" || old.Result != nil || !m.Valid() || m.Object.JobID != old.ID {
		return old, ErrConflict
	}
	n := copyJob(old)
	n.Version++
	n.Result = &m
	n.Artifact = "RESULT_PREPARED"
	n.Financial = "AWAITING_PAYMENT"
	n.ResultUntil = until
	if !validReplacement(old, n) {
		return old, ErrInvalid
	}
	return n, r.txn(ctx, []d.TransactWriteItem{r.versioned(old, n)})
}
func (r Repository) markUnknown(ctx context.Context, old Job, transaction string) (Job, error) {
	if !r.Gate.Enabled {
		return old, ErrDisabled
	}
	if !old.valid() || old.Financial != "SETTLEMENT_PENDING" || old.Settlement == nil || transaction != "" && !protocol.Hex(transaction, 32) {
		return old, ErrConflict
	}
	n := copyJob(old)
	n.Version++
	n.Financial = "PAYMENT_UNKNOWN"
	n.Settlement.State = "PAYMENT_UNKNOWN"
	n.Settlement.UnknownAt = n.Settlement.Started
	if transaction != "" {
		n.Settlement.Transaction = strings.ToLower(transaction)
	}
	if n.Artifact != "DELETING" && n.Artifact != "ERASED" {
		n.Artifact = "QUARANTINED"
	}
	if !validReplacement(old, n) {
		return old, ErrInvalid
	}
	return n, r.txn(ctx, []d.TransactWriteItem{r.versioned(old, n)})
}

// resolveFinancial performs the read-only chain lookup itself. The caller
// cannot supply a bare PAID/UNPAID outcome or manufacture its transaction field.
// The configured Chain is a trusted dependency; its production implementation
// checks the exact finalized authorization, transfer and canonical block state.
func (r Repository) resolveFinancial(ctx context.Context, old Job, chain Chain, now int64) (Job, error) {
	if !r.Gate.Enabled {
		return old, ErrDisabled
	}
	if !old.valid() || old.Financial != "PAYMENT_UNKNOWN" || old.Settlement == nil || chain == nil {
		return old, ErrConflict
	}
	outcome, e := chain.Lookup(ctx, *old.Settlement)
	if e != nil {
		return old, ErrUnknown
	}
	if outcome.State == "PAYMENT_UNKNOWN" {
		return old, nil
	}
	if outcome.State != "PAID" && outcome.State != "UNPAID" {
		return old, ErrUnknown
	}
	if outcome.State == "PAID" && (!protocol.Hex(outcome.Transaction, 32) || old.Settlement.Transaction != "" && !strings.EqualFold(old.Settlement.Transaction, outcome.Transaction)) || outcome.State == "UNPAID" && outcome.Transaction != "" {
		return old, ErrUnknown
	}
	n := copyJob(old)
	n.Version++
	n.Financial = outcome.State
	n.Settlement.State = outcome.State
	if outcome.State == "PAID" {
		n.Settlement.Transaction = strings.ToLower(outcome.Transaction)
		if n.Artifact == "ERASED" || n.Artifact == "DELETING" {
			n.Remedy = true
		} else if now >= n.Settlement.UnknownAt+24*3600 {
			n.Artifact = "DELETING"
			n.Remedy = true
		} else {
			n.Artifact = "RETRIEVABLE"
			n.ResultUntil = now + 1800
		}
	} else if n.Artifact != "ERASED" {
		n.Artifact = "DELETING"
	}
	if !validReplacement(old, n) {
		return old, ErrInvalid
	}
	if e = r.txn(ctx, []d.TransactWriteItem{r.versioned(old, n)}); e != nil {
		return old, ErrUnknown
	}
	return n, nil
}
