package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	x402 "github.com/x402-foundation/x402/go/v2"
	xhttp "github.com/x402-foundation/x402/go/v2/http"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	exact "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"github.com/x402-foundation/x402/go/v2/types"
	"pdfservice/internal/parser"
	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
)

type pricedMock struct{ settlements atomic.Int32 }

func (*pricedMock) Verify(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (bool, error) {
	return (payment.MockFacilitator{}).Verify(ctx, p, a)
}
func (f *pricedMock) Settle(ctx context.Context, p types.PaymentPayload, a evm.ExactEIP3009Payload) (*x402.SettleResponse, error) {
	f.settlements.Add(1)
	r, err := (payment.MockFacilitator{}).Settle(ctx, p, a)
	if r != nil {
		r.Amount = p.Accepted.Amount
	}
	return r, err
}

func priceHeader(t *testing.T, resource string, size int64) string {
	t.Helper()
	sig, err := signer.NewClientSignerFromPrivateKey(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := (protocol.Config{}).ForSize(size)
	p, err := x402.Newx402Client().Register(protocol.Network, exact.NewExactEvmScheme(sig, nil)).CreatePaymentPayload(context.Background(), cfg.Requirements(), cfg.Quote(resource).Resource, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Resource = cfg.Quote(resource).Resource
	h, err := protocol.Header(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestActualBytesRejectUnderpaymentBeforeParsing(t *testing.T) {
	resource := "http://example.test/v1/pdf/text"
	large := bytes.Repeat([]byte("x"), protocol.SmallPDFLimit+1)
	for _, declared := range []int64{-1, 1, protocol.SmallPDFLimit, protocol.SmallPDFLimit + 1} {
		f := &pricedMock{}
		store := &nativeTestStore{}
		pay := payment.Service{Store: store, Facilitator: f, Resource: resource}
		s := New(resource, func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
			return pay.Handle(ctx, r), nil
		}, func(context.Context, []byte) (parser.Result, error) {
			t.Fatal("underpayment reached parser")
			return parser.Result{}, nil
		})
		r := httptest.NewRequest("POST", resource, bytes.NewReader(large))
		r.ContentLength = declared
		if declared < 0 {
			r.TransferEncoding = []string{"chunked"}
		}
		r.Header.Set("Content-Type", "application/pdf")
		r.Header.Set("PAYMENT-SIGNATURE", priceHeader(t, resource, 1))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var quote types.PaymentRequired
		h, _ := base64.StdEncoding.DecodeString(w.Header().Get("PAYMENT-REQUIRED"))
		if w.Code != 402 || json.Unmarshal(h, &quote) != nil || quote.Accepts[0].Amount != protocol.LargeAmount || quote.Error != "payment_amount_mismatch" || f.settlements.Load() != 0 || len(store.rows) != 0 {
			t.Fatalf("length=%d status=%d body=%s", declared, w.Code, w.Body.String())
		}
	}
}

func TestOrdinaryX402ClientBuysBothTiersAndRetriesWithoutAnotherCharge(t *testing.T) {
	for _, size := range []int{protocol.SmallPDFLimit, protocol.SmallPDFLimit + 1, protocol.MaxPDF} {
		func() {
			var handler http.Handler
			var paidHeader atomic.Value
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if h := r.Header.Get("PAYMENT-SIGNATURE"); h != "" {
					paidHeader.Store(h)
				}
				handler.ServeHTTP(w, r)
			}))
			defer ts.Close()
			resource := ts.URL + "/v1/pdf/text"
			f := &pricedMock{}
			pay := payment.Service{Store: &nativeTestStore{}, Facilitator: f, Resource: resource}
			var parses atomic.Int32
			s := New(resource, func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				return pay.Handle(ctx, r), nil
			}, func(_ context.Context, b []byte) (parser.Result, error) {
				parses.Add(1)
				if len(b) != size {
					t.Fatal("wrong uploaded bytes")
				}
				return parser.Result{PageCount: 101, Truncated: true, Pages: []parser.Page{{Text: "bounded result"}}}, nil
			})
			handler = s.Handler()
			sig, _ := signer.NewClientSignerFromPrivateKey(strings.Repeat("0", 63) + "1")
			core := x402.Newx402Client().Register(protocol.Network, exact.NewExactEvmScheme(sig, nil))
			client := xhttp.WrapHTTPClientWithPayment(&http.Client{}, xhttp.Newx402HTTPClient(core))
			body := bytes.Repeat([]byte("x"), size)
			r, _ := http.NewRequest("POST", resource, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/pdf")
			res, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			out, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 200 || !bytes.Contains(out, []byte(`"truncated":true`)) || f.settlements.Load() != 1 || parses.Load() != 1 {
				t.Fatalf("size=%d status=%d out=%s", size, res.StatusCode, out)
			}
			for attempt := 0; attempt < 4; attempt++ {
				r, _ = http.NewRequest("POST", resource, bytes.NewReader(body))
				r.Header.Set("Content-Type", "application/pdf")
				r.Header.Set("PAYMENT-SIGNATURE", paidHeader.Load().(string))
				res, err = ts.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				want := 200
				if attempt == 3 {
					want = 429
				}
				if res.StatusCode != want || f.settlements.Load() != 1 {
					t.Fatalf("retry=%d status=%d settlements=%d", attempt, res.StatusCode, f.settlements.Load())
				}
			}
			if parses.Load() != 4 {
				t.Fatal("extra retry reached parser")
			}
		}()
	}
}

func TestLargeFailuresNeverCollectOrReleaseParsedText(t *testing.T) {
	resource := "http://example.test/v1/pdf/text"
	body := bytes.Repeat([]byte("x"), protocol.SmallPDFLimit+1)
	for _, scenario := range []string{"document", "service", "encoding", "provider"} {
		t.Run(scenario, func(t *testing.T) {
			store := &nativeTestStore{}
			f := &pricedMock{}
			pay := payment.Service{Store: store, Facilitator: f, Resource: resource}
			s := New(resource, func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				if scenario == "provider" && !r.VerifyOnly && !r.CheckDocument && !r.DocumentFailed && r.RecordOutcome == "" {
					return protocol.PaymentResponse{}, errors.New("private provider diagnostic")
				}
				return pay.Handle(ctx, r), nil
			}, func(context.Context, []byte) (parser.Result, error) {
				result := parser.Result{Pages: []parser.Page{{Text: "private extracted canary"}}}
				switch scenario {
				case "document":
					result.Attempts = []parser.Attempt{{Engine: "pdfium", Outcome: "document_error"}, {Engine: "poppler", Outcome: "document_error"}}
					return result, parser.ErrDocument
				case "service":
					return result, parser.ErrSetup
				case "encoding":
					result.Pages[0].Width = math.NaN()
				}
				return result, nil
			})
			r := httptest.NewRequest("POST", resource, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", priceHeader(t, resource, int64(len(body))))
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			want := 502
			if scenario == "document" {
				want = 422
			}
			if w.Code != want || f.settlements.Load() != 0 || len(store.rows) != 0 || strings.Contains(w.Body.String(), "private extracted canary") || strings.Contains(w.Body.String(), "private provider diagnostic") {
				t.Fatalf("scenario=%s status=%d body=%s", scenario, w.Code, w.Body.String())
			}
			if scenario == "document" {
				// A fresh independent payment cannot make the same failed PDF
				// consume another parsing attempt; no payment is collected.
				s.Parse = func(context.Context, []byte) (parser.Result, error) {
					t.Fatal("known failure was parsed again")
					return parser.Result{}, nil
				}
				r = httptest.NewRequest("POST", resource, bytes.NewReader(body))
				r.Header.Set("Content-Type", "application/pdf")
				r.Header.Set("PAYMENT-SIGNATURE", priceHeader(t, resource, int64(len(body))))
				w = httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != 422 || !strings.Contains(w.Body.String(), "document_known_unparseable") || f.settlements.Load() != 0 {
					t.Fatal("failed hash did not apply across payments")
				}
			}
		})
	}
}
