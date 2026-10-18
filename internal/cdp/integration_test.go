package cdp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	x402 "github.com/x402-foundation/x402/go/v2"
	xhttp "github.com/x402-foundation/x402/go/v2/http"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	exact "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/parser"
	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
	"pdfservice/internal/server"
)

type integrationStore struct {
	mu        sync.Mutex
	rows      map[string]payment.Binding
	failWrite bool
	failures  map[string]int64
	quotas    map[string][3]int64
}

func (s *integrationStore) GetFailureQuota(_ context.Context, key string, now int64) (payment.FailureQuota, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.quotas[key]
	if !ok || record[1] <= now {
		return payment.FailureQuota{}, nil
	}
	return payment.FailureQuota{Unpaid: record[0], Abandonments: record[2], ExpiresAt: record[1]}, nil
}

func (s *integrationStore) IncrementFailureQuota(_ context.Context, key string, expiresAt int64, eventID, eventType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quotas == nil {
		s.quotas = map[string][3]int64{}
	}
	record := s.quotas[key]
	if eventType == "abandoned" {
		record[2]++
	} else {
		record[0]++
	}
	record[1] = expiresAt
	s.quotas[key] = record
	return nil
}

func (s *integrationStore) Get(_ context.Context, key string) (*payment.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rows[key]
	if !ok {
		return nil, nil
	}
	return &b, nil
}
func (s *integrationStore) Put(_ context.Context, b payment.Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite {
		return errors.New("storage unavailable")
	}
	if s.rows == nil {
		s.rows = map[string]payment.Binding{}
	}
	if _, ok := s.rows[b.PaymentKey]; ok {
		return payment.ErrConflict
	}
	s.rows[b.PaymentKey] = b
	return nil
}

func (s *integrationStore) Complete(_ context.Context, b payment.Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite {
		return errors.New("storage unavailable")
	}
	old, ok := s.rows[b.PaymentKey]
	if !ok || old.ReservationID != b.ReservationID || old.State != "prepared" {
		return payment.ErrConflict
	}
	s.rows[b.PaymentKey] = b
	return nil
}
func (s *integrationStore) ClaimRetry(_ context.Context, b payment.Binding, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.rows[b.PaymentKey]
	if !ok || old.Transaction != b.Transaction || now >= old.RetryUntil || old.RetryCount >= payment.MaxPaidRetries {
		return payment.ErrRetryLimit
	}
	old.RetryCount++
	s.rows[b.PaymentKey] = old
	return nil
}

// This exercises the real HTTP/JWT adapter through the service and an ordinary
// official x402 client. Only the provider transport and parser are test doubles;
// no blockchain transaction or network Coinbase request occurs.
func TestOfficialClientCDPFlowAndFailures(t *testing.T) {
	for _, mode := range []string{protocol.ModeBase, protocol.ModeSepolia} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := protocol.NewConfig(mode, testPayTo)
			c, _ := testClient(t)
			c, err := c.ForPayments(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var verified, settled, parsed atomic.Int32
			var scenario atomic.Int32 // 1=invalid verification, 2=provider outage, 3=pending, 4=wrong network, 5..7=KYT verification rejection
			c.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				var body struct {
					Version      int                       `json:"x402Version"`
					Payload      types.PaymentPayload      `json:"paymentPayload"`
					Requirements types.PaymentRequirements `json:"paymentRequirements"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Version != 2 || body.Requirements.Network != cfg.Network() || body.Requirements.PayTo != cfg.PayTo() {
					t.Fatal("incorrect provider envelope")
				}
				// Reproduce CDP's resource-description schema limit rather than
				// accepting an envelope that the hosted facilitator rejects.
				if body.Payload.Resource == nil || utf8.RuneCountInString(body.Payload.Resource.Description) > 500 {
					return response(r, 400, `{"errorType":"invalid_request","errorMessage":"resource metadata rejected"}`), nil
				}
				var a evm.ExactEIP3009Payload
				raw, _ := json.Marshal(body.Payload.Payload)
				if json.Unmarshal(raw, &a) != nil {
					t.Fatal("invalid authorization")
				}
				if r.URL.Path == basePath+"verify" {
					verified.Add(1)
					if scenario.Load() == 1 {
						return response(r, 400, `{"isValid":false,"invalidReason":"insufficient_funds"}`), nil
					}
					if n := scenario.Load(); n >= 5 && n <= 7 {
						reasons := []string{"kyt_risk_detected", "invalid_exact_evm_payload_authorization_from_address_kyt", "invalid_exact_evm_payload_authorization_to_address_kyt"}
						return response(r, 400, `{"isValid":false,"invalidReason":"`+reasons[n-5]+`"}`), nil
					}
					chain, _ := strconv.ParseInt(strings.TrimPrefix(cfg.Network(), "eip155:"), 10, 64)
					hash, err := evm.HashEIP3009Authorization(a.Authorization, big.NewInt(chain), cfg.Asset(), cfg.TokenName(), "2")
					if err != nil {
						t.Fatal(err)
					}
					sig, _ := hex.DecodeString(strings.TrimPrefix(a.Signature, "0x"))
					valid, err := evm.VerifyEOASignature(hash, sig, common.HexToAddress(a.Authorization.From))
					if err != nil || !valid {
						t.Fatal("ordinary SDK client signed wrong token domain")
					}
					return response(r, 200, `{"isValid":true,"payer":"`+a.Authorization.From+`"}`), nil
				}
				if r.URL.Path != basePath+"settle" {
					t.Fatal("unexpected provider route")
				}
				settled.Add(1)
				if scenario.Load() == 2 {
					return response(r, 503, `{"errorMessage":"private diagnostic"}`), nil
				}
				tx := "0x" + protocol.SHA256([]byte(a.Authorization.Nonce))
				if scenario.Load() == 3 {
					return response(r, 400, `{"success":false,"errorReason":"settlement_pending","transaction":"`+tx+`","network":"`+cfg.Network()+`","payer":"`+a.Authorization.From+`"}`), nil
				}
				network := cfg.Network()
				if scenario.Load() == 4 {
					network = "wrong"
				}
				return response(r, 200, `{"success":true,"transaction":"`+tx+`","network":"`+network+`","payer":"`+a.Authorization.From+`"}`), nil
			})
			var handler http.Handler
			var lastHeader string
			var mu sync.Mutex
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if h := r.Header.Get("PAYMENT-SIGNATURE"); h != "" {
					mu.Lock()
					lastHeader = h
					mu.Unlock()
				}
				handler.ServeHTTP(w, r)
			}))
			defer ts.Close()
			resource := ts.URL + "/v1/pdf/text"
			store := &integrationStore{}
			pay := payment.Service{Config: cfg, Store: store, Facilitator: c, Resource: resource}
			app := server.NewWithConfig(resource, func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				return pay.Handle(ctx, r), nil
			}, func(context.Context, []byte) (parser.Result, error) {
				parsed.Add(1)
				return parser.Result{PageCount: 1, Pages: []parser.Page{{Text: "private parsed text"}}}, nil
			}, cfg)
			handler = app.Handler()
			sig, err := signer.NewClientSignerFromPrivateKey("0000000000000000000000000000000000000000000000000000000000000001")
			if err != nil {
				t.Fatal(err)
			}
			core := x402.Newx402Client().Register(x402.Network(cfg.Network()), exact.NewExactEvmScheme(sig, nil))
			client := xhttp.WrapHTTPClientWithPayment(&http.Client{}, xhttp.Newx402HTTPClient(core))
			req, _ := http.NewRequest("POST", resource, bytes.NewBufferString("document"))
			req.Header.Set("Content-Type", "application/pdf")
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != 200 || res.Header.Get("X-Payment-Mode") != mode || res.Header.Get("PAYMENT-RESPONSE") == "" || verified.Load() != 2 || settled.Load() != 1 || parsed.Load() != 1 {
				t.Fatal("automatic paid flow failed")
			}
			mu.Lock()
			header := lastHeader
			mu.Unlock()
			send := func(header, doc string, want int) {
				t.Helper()
				r, _ := http.NewRequest("POST", resource, bytes.NewBufferString(doc))
				r.Header.Set("Content-Type", "application/pdf")
				r.Header.Set("PAYMENT-SIGNATURE", header)
				out, e := http.DefaultClient.Do(r)
				if e != nil {
					t.Fatal(e)
				}
				defer out.Body.Close()
				raw, _ := io.ReadAll(out.Body)
				if want != 200 && strings.Contains(string(raw), "private parsed text") {
					t.Fatal("unpaid result disclosed")
				}
				if out.StatusCode != want {
					t.Fatalf("status=%d want=%d body=%s", out.StatusCode, want, raw)
				}
			}
			send(header, "document", 200)
			send(header, "different", 409)
			if verified.Load() != 2 || settled.Load() != 1 || parsed.Load() != 2 {
				t.Fatal("retry contacted consumed-nonce provider or parsed different document")
			}
			// Prove real bindings use a separate namespace from the historical mock key.
			var p types.PaymentPayload
			rawHeader, _ := base64.StdEncoding.DecodeString(header)
			_ = json.Unmarshal(rawHeader, &p)
			var a evm.ExactEIP3009Payload
			raw, _ := json.Marshal(p.Payload)
			_ = json.Unmarshal(raw, &a)
			old := protocol.SHA256([]byte(strings.Join([]string{cfg.Network(), strings.ToLower(cfg.Asset()), strings.ToLower(a.Authorization.From), strings.ToLower(a.Authorization.Nonce)}, "|")))
			if b, _ := store.Get(context.Background(), old); b != nil {
				t.Fatal("real binding shares mock namespace")
			}
			expectedParsed := int32(2)
			for _, tc := range []struct {
				scenario int32
				status   int
			}{{1, 402}, {2, 502}, {3, 502}, {4, 502}, {5, 402}, {6, 402}, {7, 402}} {
				scenario.Store(tc.scenario)
				payload, e := core.CreatePaymentPayload(context.Background(), cfg.Requirements(), cfg.Quote(resource).Resource, nil)
				if e != nil {
					t.Fatal(e)
				}
				payload.Resource = cfg.Quote(resource).Resource
				h, _ := protocol.Header(payload)
				send(h, "document", tc.status)
				if tc.scenario >= 2 && tc.scenario <= 4 {
					expectedParsed++
				}
				if parsed.Load() != expectedParsed {
					t.Fatal("incorrect authorization parse order")
				}
			}
			scenario.Store(0)
			store.failWrite = true
			payload, e := core.CreatePaymentPayload(context.Background(), cfg.Requirements(), cfg.Quote(resource).Resource, nil)
			if e != nil {
				t.Fatal(e)
			}
			payload.Resource = cfg.Quote(resource).Resource
			h, _ := protocol.Header(payload)
			send(h, "document", 502)
			if parsed.Load() != expectedParsed+1 {
				t.Fatal("settlement happened before parsing")
			}
		})
	}
}

func (s *integrationStore) Failed(_ context.Context, hash string, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now < s.failures[hash], nil
}
func (s *integrationStore) MarkFailed(_ context.Context, hash string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil {
		s.failures = map[string]int64{}
	}
	if s.failures[hash] <= now {
		s.failures[hash] = now + int64(payment.DocumentFailureLifetime/time.Second)
	}
	return nil
}
