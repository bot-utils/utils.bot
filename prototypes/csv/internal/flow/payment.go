package flow

import (
	"context"
	"time"
)

func (e *Engine) PaymentChallenge(id, cap string) (Challenge, error) {
	var out Challenge
	err := e.Store.tx(false, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Financial == "SETTLEMENT_PENDING" {
			return fail(409, "settlement_pending")
		}
		if j.Financial == "PAYMENT_UNKNOWN" {
			return fail(409, "payment_unknown")
		}
		if j.Financial == "PAID" {
			return fail(409, "already_paid")
		}
		if j.Artifact != "RESULT_PREPARED" || j.Financial != "AWAITING_PAYMENT" || j.Reservation != nil {
			return fail(409, "not_payable")
		}
		if j.ResultUntil-e.now() < 300 {
			return fail(410, "insufficient_retrieval_window")
		}
		if err := verify(j.Result, j.Manifest); err != nil {
			return err
		}
		out = Challenge{Mode: "synthetic-hmac-no-funds", Stage: "result", Resource: "/csv/jobs/" + id + "/payment", Binding: j.paymentBinding(), Amount: "mock:1", Expires: min(j.ResultUntil, e.now()+180)}
		return nil
	})
	return out, err
}
func (e *Engine) Pay(ctx context.Context, id, cap, proof string) (Status, error) {
	// Replays must read an existing reservation even if its proof has expired.
	var prior *reservation
	var owner string
	err := e.Store.tx(false, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		owner = j.Owner
		if j.Reservation != nil {
			v := *j.Reservation
			prior = &v
		}
		return nil
	})
	if err != nil {
		return Status{}, err
	}
	if prior != nil {
		if prior.ProofHash != digest([]byte(proof)) {
			return Status{}, fail(409, "settlement_already_reserved")
		}
		return e.Status(id, cap)
	}
	challenge, err := e.PaymentChallenge(id, cap)
	if err != nil {
		return Status{}, err
	}
	claim, err := e.Provider.Verify(proof, challenge, false, e.Now())
	if err != nil {
		return Status{}, err
	}
	if claim.Owner != owner {
		return Status{}, fail(402, "payment_owner_mismatch")
	}
	reservationID := random()
	call := false
	err = e.Store.tx(true, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Reservation != nil {
			if j.Reservation.ProofHash != digest([]byte(proof)) {
				return fail(409, "settlement_already_reserved")
			}
			return nil
		}
		if claim.Expires <= e.now() {
			return fail(402, "payment_expired")
		}
		if j.Artifact != "RESULT_PREPARED" || j.Financial != "AWAITING_PAYMENT" || j.ResultUntil-e.now() < 300 || j.Cancel || j.paymentBinding() != challenge.Binding {
			return fail(409, "not_payable")
		}
		if err := verify(j.Result, j.Manifest); err != nil {
			return err
		}
		j.Reservation = &reservation{ID: reservationID, ProofHash: digest([]byte(proof)), Binding: challenge.Binding, Started: e.now(), Outcome: "SETTLEMENT_PENDING"}
		j.Financial = "SETTLEMENT_PENDING"
		call = true
		return nil
	})
	if err != nil {
		return Status{}, err
	}
	if !call {
		return e.Status(id, cap)
	}
	// No provider retry. A lost write/reply after reservation is reconciled by ID.
	if e.Logger != nil {
		e.Logger.Info("csv flow", "route", "job_payment", "category", "provider_attempt", "status", 202)
	}
	outcome, providerErr := e.Provider.Settle(ctx, reservationID, claim)
	if providerErr != nil {
		outcome = "UNKNOWN"
	}
	if err = e.recordOutcome(id, reservationID, outcome, false); err != nil {
		return Status{}, err
	}
	return e.Status(id, cap)
}
func (e *Engine) recordOutcome(id, reservationID, outcome string, reconciled bool) error {
	previous, current := "", ""
	err := e.Store.tx(true, func(d *database) error {
		j := d.Jobs[id]
		if j == nil || j.Reservation == nil || j.Reservation.ID != reservationID {
			return fail(409, "reservation_conflict")
		}
		if j.Financial == "PAID" || j.Reservation.Outcome == "UNPAID" {
			return nil
		}
		previous = j.Financial
		defer func() { current = j.Financial }()
		now := e.now()
		switch outcome {
		case "PAID":
			wasUnknown := j.Financial == "PAYMENT_UNKNOWN"
			within := wasUnknown && now < j.UnknownAt+int64(UnknownWindow/time.Second)
			j.Financial = "PAID"
			j.Reservation.Outcome = "PAID"
			if j.Artifact == "ERASED" || wasUnknown && !within {
				j.erase()
				j.Remedy = true
				return nil
			}
			if within {
				j.ResultUntil = now + int64(ResultWindow/time.Second)
			}
			if j.Cancel || now >= j.ResultUntil {
				j.deleting()
				j.Remedy = true
			} else {
				j.Artifact = "RETRIEVABLE"
			}
		case "UNPAID":
			j.Financial = "UNPAID"
			j.Reservation.Outcome = "UNPAID"
			j.Code = "payment_rejected"
			j.deleting()
		default:
			j.Financial = "PAYMENT_UNKNOWN"
			j.Reservation.Outcome = "PAYMENT_UNKNOWN"
			if j.UnknownAt == 0 {
				j.UnknownAt = j.Reservation.Started
			}
			if j.Artifact != "ERASED" {
				j.Artifact = "QUARANTINED"
			}
		}
		return nil
	})
	if err == nil && previous != "" && current != previous && e.Logger != nil {
		route := "job_payment"
		if reconciled {
			route = "payment_reconcile"
		}
		source := "provider_response"
		if reconciled {
			source = "authoritative_reconciliation"
		}
		e.logFinancialTransition(route, source, current)
	}
	return err
}
func (e *Engine) Reconcile(ctx context.Context, id, cap string) (Status, error) {
	var reservationID string
	err := e.Store.tx(false, func(d *database) error {
		j, err := auth(d, id, cap)
		if err != nil {
			return err
		}
		if j.Financial != "PAYMENT_UNKNOWN" {
			return fail(409, "not_unknown")
		}
		reservationID = j.Reservation.ID
		return nil
	})
	if err != nil {
		return Status{}, err
	}
	result, err := e.Provider.Lookup(ctx, reservationID)
	if err != nil {
		return Status{}, fail(503, "payment_reconciliation_unavailable")
	}
	if err = e.recordOutcome(id, reservationID, result, true); err != nil {
		return Status{}, err
	}
	return e.Status(id, cap)
}

// Called only after the state transaction has successfully persisted. Values are
// fixed lifecycle labels; no job, payer, proof, capability or content identifiers.
func (e *Engine) logFinancialTransition(route, source, state string) {
	if e.Logger != nil {
		e.Logger.Info("csv flow", "route", route, "category", financialCategory(Status{Financial: state, Code: "payment_rejected"}), "financial_state", state, "source", source, "status", 200)
	}
}
