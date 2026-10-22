package csvcloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/protocol"
)

type fakeVerifier struct {
	calls atomic.Int32
	fail  bool
}

func (f *fakeVerifier) VerifyResult(_ context.Context, m Manifest) (Manifest, error) {
	f.calls.Add(1)
	if f.fail {
		return m, ErrIntegrity
	}
	return m, nil
}

type fakeChain struct {
	outcome Outcome
	err     error
	calls   atomic.Int32
}

func (f *fakeChain) Snapshot(context.Context, string) (int64, error) { return 100, nil }
func (f *fakeChain) Lookup(context.Context, Settlement) (Outcome, error) {
	f.calls.Add(1)
	if f.outcome.State == "" {
		return Outcome{State: "PAYMENT_UNKNOWN"}, f.err
	}
	return f.outcome, f.err
}

type fakeProvider struct {
	verifyErr      error
	rejected       bool
	verify, settle atomic.Int32
	lost           bool
	barrier        *sync.WaitGroup
}

func (f *fakeProvider) Verify(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (bool, error) {
	f.verify.Add(1)
	if f.barrier != nil {
		f.barrier.Done()
		f.barrier.Wait()
	}
	if f.verifyErr != nil {
		return false, f.verifyErr
	}
	return !f.rejected, nil
}
func (f *fakeProvider) Settle(context.Context, types.PaymentPayload, evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	f.settle.Add(1)
	if f.lost {
		return nil, errors.New("synthetic lost reply")
	}
	return &x402.SettleResponse{Success: true}, nil
}
func paymentFixture(t *testing.T) (Payments, Repository, Job, evm.ClientEvmSigner, *fakeProvider, *fakeChain) {
	t.Helper()
	key, e := crypto.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	client, e := signer.NewClientSignerFromPrivateKey("0x" + strings.ToLower(fmtHex(crypto.FromECDSA(key))))
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := protocol.NewConfig(protocol.ModeBase, "0x2222222222222222222222222222222222222222")
	if e != nil {
		t.Fatal(e)
	}
	r, _ := memoryRepo()
	j := fixtureJob()
	j.Owner = client.Address()
	seed(t, r, j)
	m, _ := manifest(j.ID)
	n := prepareSeeded(t, r, j, m)
	p := &fakeProvider{}
	c := &fakeChain{}
	s := Payments{Repo: r, Objects: &fakeVerifier{}, Bind: func(Quote) (Facilitator, error) { return p, nil }, Chain: c, Keys: Keys{Current: "v1", Versions: map[string][]byte{"v1": []byte(strings.Repeat("k", 32))}}, Config: cfg, Gate: Gate{Enabled: true, Settlement: true}, Amount: "12345", Origin: "https://utils.bot", Now: func() time.Time { return fixtureTime }}
	return s, r, n, client, p, c
}
func fmtHex(v []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(v)*2)
	for i, x := range v {
		out[i*2] = digits[x>>4]
		out[i*2+1] = digits[x&15]
	}
	return string(out)
}
func sign(t *testing.T, s Payments, q Quote, client evm.ClientEvmSigner) string {
	t.Helper()
	h, e := SignBound(ctx, client, s.Config, q, s.now())
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func mutateProof(t *testing.T, h string, f func(*types.PaymentPayload)) string {
	t.Helper()
	b, _ := base64.StdEncoding.DecodeString(h)
	var p types.PaymentPayload
	_ = json.Unmarshal(b, &p)
	f(&p)
	b, _ = json.Marshal(p)
	return base64.StdEncoding.EncodeToString(b)
}
func TestOfficialSignerRoundtripAndBoundProofNegatives(t *testing.T) {
	s, r, j, client, p, _ := paymentFixture(t)
	q, e := s.ResultQuote(ctx, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.ResultQuote(ctx, j.ID)
	if e != nil || again.ID != q.ID {
		t.Fatal("quote changed")
	}
	h := sign(t, s, q, client)
	if _, _, e = Decode(ctx, s.Keys, s.Config, q, h, s.now()); e != nil {
		t.Fatal("official signer rejected", e)
	}
	tests := map[string]func(*Quote, *types.PaymentPayload){
		"other-job":      func(q *Quote, _ *types.PaymentPayload) { q.JobID = ID() },
		"changed-input":  func(q *Quote, _ *types.PaymentPayload) { q.IntentBinding = ID() },
		"changed-result": func(q *Quote, _ *types.PaymentPayload) { q.ResultBinding = ID() },
		"wrong-stage":    func(q *Quote, _ *types.PaymentPayload) { q.Stage = "admission" },
		"expired":        func(q *Quote, _ *types.PaymentPayload) { q.Expires = fixtureTime.Unix() },
		"amount":         func(_ *Quote, p *types.PaymentPayload) { p.Accepted.Amount = "12346" },
		"receiver": func(_ *Quote, p *types.PaymentPayload) {
			p.Accepted.PayTo = "0x3333333333333333333333333333333333333333"
		},
		"network": func(_ *Quote, p *types.PaymentPayload) { p.Accepted.Network = "eip155:84532" },
		"asset": func(_ *Quote, p *types.PaymentPayload) {
			p.Accepted.Asset = "0x3333333333333333333333333333333333333333"
		},
		"random-nonce": func(_ *Quote, p *types.PaymentPayload) {
			p.Payload["authorization"].(map[string]interface{})["nonce"] = "0x" + ID()
		},
		"extension": func(_ *Quote, p *types.PaymentPayload) { p.Extensions = nil },
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := q
			bad := mutateProof(t, h, func(payload *types.PaymentPayload) { f(&candidate, payload) })
			if _, _, e := Decode(ctx, s.Keys, s.Config, candidate, bad, s.now()); e != ErrInvalid {
				t.Fatal("accepted", e)
			}
			if p.verify.Load() != 0 || p.settle.Load() != 0 || readJob(t, r, j.ID).Settlement != nil {
				t.Fatal("invalid proof reached provider/reservation")
			}
		})
	}
	old := s.Keys
	s.Keys.Current = "v2"
	s.Keys.Versions["v2"] = []byte(strings.Repeat("n", 32))
	if _, _, e = Decode(ctx, s.Keys, s.Config, q, h, s.now()); e != nil {
		t.Fatal("rotation rejected outstanding key", e)
	}
	delete(s.Keys.Versions, "v1")
	if _, _, e = Decode(ctx, s.Keys, s.Config, q, h, s.now()); e != ErrInvalid {
		t.Fatal("missing key accepted")
	}
	_ = old
}
func TestCrossJobProofRejectedBeforeProvider(t *testing.T) {
	s, r, j, client, p, _ := paymentFixture(t)
	q, e := s.ResultQuote(ctx, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	h := sign(t, s, q, client)
	other := fixtureJob()
	other.Owner = j.Owner
	seed(t, r, other)
	m, _ := manifest(other.ID)
	_ = prepareSeeded(t, r, other, m)
	if _, e = s.ResultQuote(ctx, other.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Settle(ctx, other.ID, h); e != ErrInvalid {
		t.Fatal(e)
	}
	if p.verify.Load() != 0 || p.settle.Load() != 0 {
		t.Fatal("cross-job proof reached provider")
	}
}
func TestSettlementDuplicateConcurrentUnknownThenFinal(t *testing.T) {
	s, r, j, client, p, c := paymentFixture(t)
	q, e := s.ResultQuote(ctx, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	h := sign(t, s, q, client)
	p.lost = true
	wg := &sync.WaitGroup{}
	wg.Add(2)
	p.barrier = wg
	var done sync.WaitGroup
	done.Add(2)
	for range 2 {
		go func() { defer done.Done(); _, _ = s.Settle(ctx, j.ID, h) }()
	}
	done.Wait()
	p.barrier = nil
	if p.settle.Load() != 1 {
		t.Fatal("settlement count", p.settle.Load())
	}
	unknown := readJob(t, r, j.ID)
	if unknown.Financial != "PAYMENT_UNKNOWN" || unknown.Artifact != "QUARANTINED" {
		t.Fatal(unknown.Financial, unknown.Artifact)
	}
	if _, e = s.Settle(ctx, j.ID, h); e != nil || p.settle.Load() != 1 {
		t.Fatal("settled again", e)
	}
	c.outcome = Outcome{State: "PAID", Transaction: "0x" + ID()}
	paid, e := s.Reconcile(ctx, j.ID)
	if e != nil || paid.Financial != "PAID" || paid.Artifact != "RETRIEVABLE" {
		t.Fatal(e)
	}
	if p.settle.Load() != 1 {
		t.Fatal("reconcile settled")
	}
}
func TestProviderSuccessDoesNotReleaseWithoutFinality(t *testing.T) {
	s, r, j, client, p, _ := paymentFixture(t)
	q, _ := s.ResultQuote(ctx, j.ID)
	if _, e := s.Settle(ctx, j.ID, sign(t, s, q, client)); e != nil {
		t.Fatal(e)
	}
	got := readJob(t, r, j.ID)
	if got.Artifact != "QUARANTINED" || got.Financial != "PAYMENT_UNKNOWN" || p.settle.Load() != 1 {
		t.Fatal("provider success released artifact")
	}
}
func TestCrashExpiryAndLatePaidRemedy(t *testing.T) {
	s, r, j, client, p, c := paymentFixture(t)
	q, _ := s.ResultQuote(ctx, j.ID)
	h := sign(t, s, q, client)
	_, a, e := Decode(ctx, s.Keys, s.Config, q, h, s.now())
	if e != nil {
		t.Fatal(e)
	}
	old := readJob(t, r, j.ID)
	reservation := Settlement{ID: ID(), Nonce: a.Authorization.Nonce, Payer: strings.ToLower(client.Address()), Receiver: q.Receiver, Asset: q.Asset, Network: q.Network, Amount: q.Amount, ValidBefore: q.Expires, Started: fixtureTime.Unix(), StartBlock: q.StartBlock}
	if _, e = r.ReserveSettlement(ctx, old, reservation, ID()); e != nil {
		t.Fatal(e)
	}
	if e = s.RecoverPending(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	s.Now = func() time.Time { return fixtureTime.Add(25 * time.Hour) }
	if e = s.Expire(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	if readJob(t, r, j.ID).Artifact != "DELETING" {
		t.Fatal("privacy cap")
	}
	c.outcome = Outcome{State: "PAID", Transaction: "0x" + ID()}
	got, e := s.Reconcile(ctx, j.ID)
	if e != nil || !got.Remedy || got.Artifact != "DELETING" || p.settle.Load() != 0 {
		t.Fatal("late paid resurrected result", e)
	}
}
func TestAdmissionStatelessNoSettlementAndDefaultOff(t *testing.T) {
	s, r, j, client, p, _ := paymentFixture(t)
	q, e := AdmissionQuote(s.Keys, s.Config, j.IntentBinding, s.Amount, s.Origin+"/csv/uploads", s.now())
	if e != nil {
		t.Fatal(e)
	}
	h := sign(t, s, q, client)
	payer, nonce, e := s.VerifyAdmission(ctx, q, h)
	if e != nil || !strings.EqualFold(payer, client.Address()) || !opaque(nonce) || p.verify.Load() != 1 || p.settle.Load() != 0 {
		t.Fatal(e)
	}
	if readJob(t, r, j.ID).Version != j.Version {
		t.Fatal("admission allocated data")
	}
	s.Gate.Settlement = false
	if _, e = s.Settle(ctx, j.ID, h); e != ErrDisabled || p.settle.Load() != 0 {
		t.Fatal(e)
	}
	s.Gate = Gate{}
	if _, _, e = s.VerifyAdmission(ctx, q, h); e != ErrDisabled {
		t.Fatal(e)
	}
}

type fenceStub struct {
	err   error
	calls int
}

func (f *fenceStub) VerifyStopped(context.Context, Job) error { f.calls++; return f.err }

type eraseStub struct {
	err   error
	calls int
}

func (f *eraseStub) EraseAndVerify(context.Context, Job) error { f.calls++; return f.err }
func TestVerifiedCleanupScrubsOnceAndRetainsUnknownFinancialEvidence(t *testing.T) {
	s, r, j, client, _, _ := paymentFixture(t)
	q, _ := s.ResultQuote(ctx, j.ID)
	s.Bind = func(Quote) (Facilitator, error) { return &fakeProvider{lost: true}, nil }
	if _, e := s.Settle(ctx, j.ID, sign(t, s, q, client)); e != nil {
		t.Fatal(e)
	}
	s.Now = func() time.Time { return fixtureTime.Add(25 * time.Hour) }
	if e := s.Expire(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	w := &fenceStub{err: ErrUnknown}
	o := &eraseStub{}
	c := Cleanup{Repo: r, Writers: w, Objects: o, Gate: Gate{Enabled: true}}
	if e := c.Complete(ctx, j.ID); e != ErrCleanup || o.calls != 0 {
		t.Fatal("deleted before stopped fence")
	}
	w.err = nil
	o.err = ErrCleanup
	if e := c.Complete(ctx, j.ID); e != ErrCleanup || readJob(t, r, j.ID).Artifact != "DELETING" {
		t.Fatal("cleanup uncertainty released capacity")
	}
	o.err = nil
	if e := c.Complete(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	erased := readJob(t, r, j.ID)
	if erased.Artifact != "ERASED" || erased.Financial != "PAYMENT_UNKNOWN" || erased.Settlement == nil || erased.Result != nil || erased.Inputs != nil || erased.Quote != nil || erased.Owner != "" || erased.IntentBinding != "" || erased.CapabilityVerifier != "" {
		t.Fatal("metadata retained")
	}
	before := erased.Version
	if e := c.Complete(ctx, j.ID); e != nil || readJob(t, r, j.ID).Version != before {
		t.Fatal("cleanup repeated")
	}
	chain := s.Chain.(*fakeChain)
	chain.outcome = Outcome{State: "PAID", Transaction: "0x" + ID()}
	got, e := s.Reconcile(ctx, j.ID)
	if e != nil || got.Artifact != "ERASED" || !got.Remedy {
		t.Fatal("erased paid result resurrected", e)
	}
}

// Exercise every controller lifecycle step instead of seeding skipped states.
func prepareSeeded(t *testing.T, r Repository, j Job, m Manifest) Job {
	t.Helper()
	a := Artifacts{Repo: r, Inputs: inputStub{}, Results: &fakeVerifier{}, Gate: Gate{Enabled: true}, Now: func() time.Time { return fixtureTime }}
	if e := a.AcceptUploads(ctx, j.ID); e != nil {
		t.Fatal(e)
	}
	verified := readJob(t, r, j.ID)
	q, e := r.Queue(ctx, verified, ID(), 100, 200)
	if e != nil {
		t.Fatal(e)
	}
	reserved := copyJob(q)
	reserved.Version++
	reserved.Artifact = "DISPATCH_RESERVED"
	reserved.Dispatch.State = "STARTING"
	reserved.Dispatch.Started = fixtureTime.Unix()
	reserved.Dispatch.Parameters = ID()
	if e = r.Replace(ctx, q, reserved); e != nil {
		t.Fatal(e)
	}
	running := copyJob(reserved)
	running.Version++
	running.Artifact = "RUNNING"
	running.Dispatch.State = "ACTIVE"
	running.Dispatch.TaskARN = "arn:synthetic:owned"
	if e = r.Replace(ctx, reserved, running); e != nil {
		t.Fatal(e)
	}
	if e = a.PublishResult(ctx, j.ID, running.Dispatch.Token, m, fixtureTime.Unix()+1800); e != nil {
		t.Fatal(e)
	}
	return readJob(t, r, j.ID)
}

type eventCollector struct {
	mu     sync.Mutex
	events []Event
}

func (c *eventCollector) Count(_ context.Context, e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}
func (c *eventCollector) contains(e Event) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range c.events {
		if e == v {
			return true
		}
	}
	return false
}

type unavailableRepo struct{ JobRepository }

func (unavailableRepo) Get(context.Context, string) (*Job, error) { return nil, ErrUnknown }
func TestTelemetrySeparatesProviderUncertaintyAdmissionRejectionAndInfrastructure(t *testing.T) {
	s, r, j, client, p, _ := paymentFixture(t)
	events := &eventCollector{}
	s.Events = events
	q, e := s.AdmissionChallenge(ctx, j.IntentBinding)
	if e != nil || !events.contains(InitialQuote) {
		t.Fatal(e)
	}
	h := sign(t, s, q, client)
	p.verifyErr = ErrUnknown
	if _, _, e = s.VerifyAdmission(ctx, q, h); e != ErrUnknown || !events.contains(ProviderVerifyFailure) || events.contains(PaymentRejected) {
		t.Fatal("admission provider uncertainty misclassified")
	}
	p.verifyErr = nil
	p.rejected = true
	if _, _, e = s.VerifyAdmission(ctx, q, h); e != ErrInvalid || !events.contains(PaymentRejected) {
		t.Fatal("admission rejection not classified")
	}
	p.rejected = false
	events.events = nil
	p.lost = true
	result, e := s.ResultQuote(ctx, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Settle(ctx, j.ID, sign(t, s, result, client)); e != nil {
		t.Fatal(e)
	}
	if !events.contains(ProviderSettleFailure) || !events.contains(PaymentUnknown) || events.contains(PaymentRejected) || readJob(t, r, j.ID).Financial != "PAYMENT_UNKNOWN" {
		t.Fatal("settlement error treated as rejection")
	}
	for _, e := range events.events {
		if e.Record().PayerRejected {
			t.Fatal("uncertain payment counted as payer rejection")
		}
	}
	s.Repo = unavailableRepo{r}
	if _, e = s.ResultQuote(ctx, j.ID); e == nil || !events.contains(InfrastructureFailure) {
		t.Fatal("infrastructure error not classified")
	}
}
func TestPersistedSettlementStateIsClosedAndConsistent(t *testing.T) {
	s, r, j, client, p, _ := paymentFixture(t)
	q, _ := s.ResultQuote(ctx, j.ID)
	p.lost = true
	if _, e := s.Settle(ctx, j.ID, sign(t, s, q, client)); e != nil {
		t.Fatal(e)
	}
	got := readJob(t, r, j.ID)
	for _, state := range []string{"free-form diagnostic", "PAID", "UNPAID", ""} {
		bad := copyJob(got)
		bad.Settlement.State = state
		if bad.valid() {
			t.Fatal("invalid/mismatched settlement state accepted", state)
		}
	}
}

func TestGenericReplacementCannotBypassNonceReservation(t *testing.T) {
	_, r, j, _, _, _ := paymentFixture(t)
	n := copyJob(j)
	n.Version++
	n.Financial = "SETTLEMENT_PENDING"
	n.Settlement = &Settlement{ID: ID(), Nonce: "0x" + ID(), Payer: j.Owner, Receiver: "0x2222222222222222222222222222222222222222", Asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", Network: "eip155:8453", Amount: "12345", State: "SETTLEMENT_PENDING", Started: fixtureTime.Unix(), ValidBefore: fixtureTime.Unix() + 180}
	if !n.valid() {
		t.Fatal("fixture must isolate reservation rule")
	}
	if e := r.Replace(ctx, j, n); e != ErrInvalid {
		t.Fatal("settlement bypassed atomic nonce transaction", e)
	}
}
