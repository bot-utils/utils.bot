package csvcloud

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"pdfservice/internal/cdp"
	"pdfservice/internal/protocol"
)

type JobRepository interface {
	Get(context.Context, string) (*Job, error)
	Replace(context.Context, Job, Job) error
	ReserveSettlement(context.Context, Job, Settlement, string) (Job, error)
}
type ResultVerifier interface {
	VerifyResult(context.Context, Manifest) (Manifest, error)
}
type Payments struct {
	Events         EventSink
	Repo           JobRepository
	Objects        ResultVerifier
	Provider       *cdp.Client
	Bind           func(Quote) (Facilitator, error)
	Chain          Chain
	Keys           Keys
	Config         protocol.Config
	Gate           Gate
	Amount, Origin string
	Now            func() time.Time
}

func (s Payments) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
func copyJob(j Job) Job {
	raw, _ := json.Marshal(j)
	var copy Job
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func (s Payments) facilitator(q Quote) (Facilitator, error) {
	if s.Bind != nil {
		return s.Bind(q)
	}
	if s.Provider == nil {
		return nil, ErrDisabled
	}
	return s.Provider.ForTabular(s.Config, Requirements(s.Config, q.Amount), q.Resource)
}

// ResultQuote is issued only for a fully verified immutable prepared result.
// Active reads return the same quote. An expired quote is explicitly superseded.
func (s Payments) ResultQuote(ctx context.Context, id string) (Quote, error) {
	if !s.Gate.Enabled {
		return Quote{}, ErrDisabled
	}
	if !validAmount(s.Amount) || !validOrigin(s.Origin) || s.Config.Mode() == protocol.ModeMock {
		return Quote{}, ErrInvalid
	}
	j, err := s.Repo.Get(ctx, id)
	if err != nil {
		return Quote{}, err
	}
	now := s.now().Unix()
	if j == nil || j.Artifact != "RESULT_PREPARED" || j.Financial != "AWAITING_PAYMENT" || j.Settlement != nil || j.Result == nil || !j.Result.Valid() || j.ResultUntil-now < 300 {
		return Quote{}, ErrConflict
	}
	if j.Quote != nil && j.Quote.Expires > now {
		return *j.Quote, nil
	}
	if j.QuoteCount >= 3 {
		return Quote{}, ErrConflict
	}
	if _, err = s.Objects.VerifyResult(ctx, *j.Result); err != nil {
		s.event(ctx, DocumentFailure)
		return Quote{}, err
	}
	block, err := s.Chain.Snapshot(ctx, s.Config.Network())
	if err != nil {
		return Quote{}, ErrUnknown
	}
	q, err := s.Keys.issue(Quote{ID: ID(), Stage: "result", JobID: j.ID, Owner: strings.ToLower(j.Owner), IntentBinding: j.IntentBinding, ResultBinding: resultDigest(*j.Result), Resource: s.Origin + "/csv/jobs/" + j.ID + "/payment", Amount: s.Amount, Network: s.Config.Network(), Asset: strings.ToLower(s.Config.Asset()), Receiver: strings.ToLower(s.Config.PayTo()), Expires: now + 180, StartBlock: block}, now)
	if err != nil {
		return q, err
	}
	next := copyJob(*j)
	next.Version++
	next.Quote = &q
	next.QuoteCount++
	if err = s.Repo.Replace(ctx, *j, next); err != nil {
		return Quote{}, err
	}
	s.event(ctx, Requote)
	return q, nil
}
func (s Payments) Settle(ctx context.Context, id, proof string) (*Job, error) {
	// No executable or public route enables this flag in this implementation.
	if !s.Gate.Enabled || !s.Gate.Settlement {
		return nil, ErrDisabled
	}
	j, err := s.Repo.Get(ctx, id)
	if err != nil || j == nil {
		return j, ErrConflict
	}
	if j.Settlement != nil {
		return j, nil
	}
	if j.Financial != "AWAITING_PAYMENT" || j.Artifact != "RESULT_PREPARED" || j.Result == nil || !j.Result.Valid() || j.Quote == nil || j.ResultUntil-s.now().Unix() < 300 {
		return j, ErrConflict
	}
	q := *j.Quote
	if q.JobID != j.ID || !strings.EqualFold(q.Owner, j.Owner) || q.Stage != "result" || q.IntentBinding != j.IntentBinding || q.ResultBinding != resultDigest(*j.Result) {
		return j, ErrConflict
	}
	p, a, err := Decode(ctx, s.Keys, s.Config, q, proof, s.now())
	if err != nil {
		s.event(ctx, MalformedPayment)
		return j, err
	}
	if _, err = s.Objects.VerifyResult(ctx, *j.Result); err != nil {
		return j, err
	}
	provider, err := s.facilitator(q)
	if err != nil {
		return j, err
	}
	valid, err := provider.Verify(ctx, p, a)
	if err != nil {
		s.event(ctx, ProviderVerifyFailure)
		return j, ErrUnknown
	}
	if !valid {
		s.event(ctx, PaymentRejected)
		return j, ErrInvalid
	}
	before, _ := strconv.ParseInt(a.Authorization.ValidBefore, 10, 64)
	if s.now().Unix() >= before || j.ResultUntil-s.now().Unix() < 300 {
		return j, ErrInvalid
	}
	nonceKey := Hash([]byte(strings.ToLower(q.Network + "|" + q.Asset + "|" + a.Authorization.From + "|" + a.Authorization.Nonce)))
	reservation := Settlement{ID: ID(), Nonce: strings.ToLower(a.Authorization.Nonce), Payer: strings.ToLower(a.Authorization.From), Receiver: q.Receiver, Asset: q.Asset, Network: q.Network, Amount: q.Amount, ValidBefore: before, Started: s.now().Unix(), StartBlock: q.StartBlock}
	pending, err := s.Repo.ReserveSettlement(ctx, *j, reservation, nonceKey)
	if err != nil {
		return nil, err
	}
	receipt, providerErr := provider.Settle(ctx, p, a) // exactly one call, never a reconcile retry
	if providerErr != nil {
		s.event(ctx, ProviderSettleFailure)
	}
	s.event(ctx, PaymentUnknown)
	next := copyJob(pending)
	next.Version++
	next.Financial = "PAYMENT_UNKNOWN"
	next.Artifact = "QUARANTINED"
	next.Settlement.State = "PAYMENT_UNKNOWN"
	next.Settlement.UnknownAt = s.now().Unix()
	if providerErr == nil && receipt != nil && protocol.Hex(receipt.Transaction, 32) && string(receipt.Network) == q.Network && strings.EqualFold(receipt.Payer, j.Owner) {
		next.Settlement.Transaction = strings.ToLower(receipt.Transaction)
	}
	if err = s.Repo.Replace(ctx, pending, next); err != nil {
		return nil, ErrUnknown
	}
	// Provider success/submission alone never releases the artifact. The selected
	// finalized chain policy is checked read-only using the original authorization.
	return s.Reconcile(ctx, id)
}
func (s Payments) Reconcile(ctx context.Context, id string) (*Job, error) {
	if !s.Gate.Enabled {
		return nil, ErrDisabled
	}
	j, err := s.Repo.Get(ctx, id)
	if err != nil || j == nil {
		return j, ErrConflict
	}
	if j.Financial == "PAID" || j.Financial == "UNPAID" {
		return j, nil
	}
	if j.Settlement == nil || j.Financial != "PAYMENT_UNKNOWN" && j.Financial != "SETTLEMENT_PENDING" {
		return j, ErrConflict
	}
	if j.Financial == "SETTLEMENT_PENDING" {
		if err = s.RecoverPending(ctx, id); err != nil {
			return j, err
		}
		j, err = s.Repo.Get(ctx, id)
		if err != nil || j == nil {
			return nil, ErrUnknown
		}
	}
	outcome, err := s.Chain.Lookup(ctx, *j.Settlement)
	if err != nil {
		return j, ErrUnknown
	}
	if outcome.State == "PAYMENT_UNKNOWN" {
		return j, nil
	}
	if outcome.State != "PAID" && outcome.State != "UNPAID" {
		return j, ErrUnknown
	}
	next := copyJob(*j)
	next.Version++
	next.Financial = outcome.State
	next.Settlement.State = outcome.State
	if outcome.State == "PAID" {
		next.Settlement.Transaction = outcome.Transaction
		if next.Artifact == "ERASED" || next.Artifact == "DELETING" {
			next.Remedy = true
		} else if s.now().Unix() >= next.Settlement.UnknownAt+24*3600 {
			next.Artifact = "DELETING"
			next.Remedy = true
		} else {
			next.Artifact = "RETRIEVABLE"
			next.ResultUntil = s.now().Add(30 * time.Minute).Unix()
		}
	} else {
		next.Artifact = "DELETING"
	}
	if err = s.Repo.Replace(ctx, *j, next); err != nil {
		return nil, ErrUnknown
	}
	if next.Financial == "PAID" {
		s.event(ctx, PaymentFinalized)
	}
	return &next, nil
}

// RecoverPending never calls the facilitator. A crash before/after its one call
// is represented identically until finalized chain evidence resolves it.
func (s Payments) RecoverPending(ctx context.Context, id string) error {
	if !s.Gate.Enabled {
		return ErrDisabled
	}
	j, err := s.Repo.Get(ctx, id)
	if err != nil || j == nil || j.Settlement == nil {
		return ErrConflict
	}
	if j.Financial != "SETTLEMENT_PENDING" {
		return nil
	}
	next := copyJob(*j)
	next.Version++
	next.Financial = "PAYMENT_UNKNOWN"
	next.Artifact = "QUARANTINED"
	next.Settlement.State = "PAYMENT_UNKNOWN"
	next.Settlement.UnknownAt = next.Settlement.Started
	return s.Repo.Replace(ctx, *j, next)
}

// VerifyAdmission performs real signature/provider verification without settling
// or allocating storage. The caller uses its recovered payer/nonce to create the
// intent through the repository's atomic nonce/idempotency/capacity transaction.
func (s Payments) VerifyAdmission(ctx context.Context, q Quote, proof string) (string, string, error) {
	if !s.Gate.Enabled {
		return "", "", ErrDisabled
	}
	if q.Stage != "admission" || q.JobID != "" || q.Owner != "" || q.ResultBinding != "" {
		return "", "", ErrInvalid
	}
	p, a, err := Decode(ctx, s.Keys, s.Config, q, proof, s.now())
	if err != nil {
		return "", "", err
	}
	provider, err := s.facilitator(q)
	if err != nil {
		return "", "", err
	}
	valid, err := provider.Verify(ctx, p, a)
	if err != nil {
		return "", "", ErrUnknown
	}
	if !valid {
		return "", "", ErrInvalid
	}
	key := Hash([]byte(strings.ToLower(q.Network + "|" + q.Asset + "|" + a.Authorization.From + "|" + a.Authorization.Nonce)))
	return strings.ToLower(a.Authorization.From), key, nil
}
func (s Payments) Expire(ctx context.Context, id string) error {
	if !s.Gate.Enabled {
		return ErrDisabled
	}
	j, err := s.Repo.Get(ctx, id)
	if err != nil || j == nil {
		return ErrConflict
	}
	if j.Financial == "SETTLEMENT_PENDING" {
		return s.RecoverPending(ctx, id)
	}
	now := s.now().Unix()
	expired := j.Financial == "PAYMENT_UNKNOWN" && j.Settlement != nil && now >= j.Settlement.UnknownAt+24*3600 || j.Financial != "PAYMENT_UNKNOWN" && (j.ResultUntil > 0 && now >= j.ResultUntil || j.ResultUntil == 0 && now >= j.UploadUntil)
	if !expired || j.Artifact == "ERASED" || j.Artifact == "DELETING" {
		return nil
	}
	next := copyJob(*j)
	next.Version++
	next.Artifact = "DELETING"
	if j.Financial == "PAYMENT_UNKNOWN" {
		next.Remedy = true
	}
	return s.Repo.Replace(ctx, *j, next)
}

// AdmissionChallenge is the expected unsigned 402 stage; no job/resource is
// allocated and no provider is contacted until a signed proof is presented.
func (s Payments) AdmissionChallenge(ctx context.Context, intentBinding string) (Quote, error) {
	if !s.Gate.Enabled {
		return Quote{}, ErrDisabled
	}
	if !validOrigin(s.Origin) {
		return Quote{}, ErrInvalid
	}
	q, e := AdmissionQuote(s.Keys, s.Config, intentBinding, s.Amount, s.Origin+"/csv/uploads", s.now())
	if e == nil {
		s.event(ctx, InitialQuote)
	}
	return q, e
}
