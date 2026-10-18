package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	x402 "github.com/x402-foundation/x402/go/v2"
	xhttp "github.com/x402-foundation/x402/go/v2/http"
	exact "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	signer "github.com/x402-foundation/x402/go/v2/signers/evm"
	"pdfservice/internal/parser"
	"pdfservice/internal/payment"
	"pdfservice/internal/protocol"
)

type nativeTestStore struct {
	mu       sync.Mutex
	rows     map[string]payment.Binding
	failures map[string]int64
	quotas   map[string][3]int64
}

func (s *nativeTestStore) GetFailureQuota(_ context.Context, key string, now int64) (payment.FailureQuota, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.quotas[key]
	if !ok || record[1] <= now {
		return payment.FailureQuota{}, nil
	}
	return payment.FailureQuota{Unpaid: record[0], Abandonments: record[2], ExpiresAt: record[1]}, nil
}

func (s *nativeTestStore) IncrementFailureQuota(_ context.Context, key string, expiresAt int64, eventID, eventType string) error {
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

func (s *nativeTestStore) Get(ctx context.Context, k string) (*payment.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rows[k]
	if !ok {
		return nil, nil
	}
	return &b, nil
}
func (s *nativeTestStore) Put(ctx context.Context, b payment.Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows == nil {
		s.rows = map[string]payment.Binding{}
	}
	if _, ok := s.rows[b.PaymentKey]; ok {
		return payment.ErrConflict
	}
	s.rows[b.PaymentKey] = b
	return nil
}
func (s *nativeTestStore) Complete(_ context.Context, b payment.Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.rows[b.PaymentKey]
	if !ok || old.State != "prepared" || old.ReservationID != b.ReservationID {
		return payment.ErrConflict
	}
	s.rows[b.PaymentKey] = b
	return nil
}
func (s *nativeTestStore) ClaimRetry(_ context.Context, b payment.Binding, now int64) error {
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

func TestOfficialClientNativeFlow(t *testing.T) {
	if os.Getenv("PDF_NATIVE_TEST") != "1" {
		t.Skip("run scripts/test-native.sh for full native HTTP flow")
	}
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
	store := &nativeTestStore{}
	pay := payment.Service{Store: store, Facilitator: payment.MockFacilitator{}, Resource: resource}
	native := parser.Parser{Dir: "/app"}
	var parseCalls atomic.Int32
	app := New(resource, func(ctx context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		return pay.Handle(ctx, r), nil
	}, func(ctx context.Context, body []byte) (parser.Result, error) {
		parseCalls.Add(1)
		return native.Parse(ctx, body)
	})
	handler = app.Handler()
	s, err := signer.NewClientSignerFromPrivateKey("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	core := x402.Newx402Client().Register(protocol.Network, exact.NewExactEvmScheme(s, nil))
	client := xhttp.WrapHTTPClientWithPayment(&http.Client{}, xhttp.Newx402HTTPClient(core))
	data, err := os.ReadFile("/testdata/hello.pdf")
	if err != nil {
		t.Fatal(err)
	}
	// Exceeds the planned future Lambda threshold, through a single customer POST.
	large := make([]byte, 5<<20)
	copy(large, data)
	for i := len(data); i < len(large); i++ {
		large[i] = '\n'
	}
	req, _ := http.NewRequest("POST", resource, bytes.NewReader(large))
	req.Header.Set("Content-Type", "application/pdf")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 {
		t.Fatalf("automatic x402 handshake: %d %s", response.StatusCode, raw)
	}
	var out struct {
		parser.Result
		BodySHA256 string `json:"bodySHA256"`
	}
	if json.Unmarshal(raw, &out) != nil || len(out.Pages) != 1 || out.BodySHA256 != protocol.SHA256(large) {
		t.Fatalf("bad response %s", raw)
	}
	if response.Header.Get("PAYMENT-RESPONSE") == "" {
		t.Fatal("missing settlement header")
	}
	mu.Lock()
	paidHeader := lastHeader
	mu.Unlock()
	for _, test := range []struct {
		name   string
		body   []byte
		status int
	}{{"same-file retry", large, 200}, {"different-file rejection", data, 409}} {
		t.Run(test.name, func(t *testing.T) {
			r, _ := http.NewRequest("POST", resource, bytes.NewReader(test.body))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", paidHeader)
			result, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Body.Close()
			body, _ := io.ReadAll(result.Body)
			if result.StatusCode != test.status {
				t.Fatalf("status=%d body=%s", result.StatusCode, body)
			}
		})
	}
	if len(store.rows) != 1 {
		t.Fatalf("bindings=%d", len(store.rows))
	}
	t.Run("maximum-size benign upload", func(t *testing.T) {
		// A padded ordinary PDF validates ingress/allocation at the size limit;
		// it does not establish worst-case memory use for complex documents.
		body := bytes.Repeat([]byte{'\n'}, protocol.MaxPDF)
		copy(body, data)
		r, _ := http.NewRequest("POST", resource, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/pdf")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		if response.StatusCode != 200 {
			t.Fatalf("maximum-size upload: %d %s", response.StatusCode, raw)
		}
		var out struct {
			parser.Result
			BodySHA256 string `json:"bodySHA256"`
		}
		if json.Unmarshal(raw, &out) != nil || len(out.Pages) != 1 || out.BodySHA256 != protocol.SHA256(body) {
			t.Fatalf("bad maximum-size response %s", raw)
		}
	})
	t.Run("failed native waterfall is uncharged and exact repeat skips workers", func(t *testing.T) {
		bad, err := os.ReadFile("/testdata/bad.pdf")
		if err != nil {
			t.Fatal(err)
		}
		beforeRows, beforeParses := len(store.rows), parseCalls.Load()
		r, _ := http.NewRequest("POST", resource, bytes.NewReader(bad))
		r.Header.Set("Content-Type", "application/pdf")
		first, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(first.Body)
		first.Body.Close()
		var out struct {
			parser.Result
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &out) != nil || first.StatusCode != 422 || len(out.Attempts) != 2 || out.Error != "document_parse_failed" || first.Header.Get("PAYMENT-RESPONSE") != "" {
			t.Fatalf("failed native waterfall: %d %s", first.StatusCode, raw)
		}
		mu.Lock()
		failedHeader := lastHeader
		mu.Unlock()
		r, _ = http.NewRequest("POST", resource, bytes.NewReader(bad))
		r.Header.Set("Content-Type", "application/pdf")
		r.Header.Set("PAYMENT-SIGNATURE", failedHeader)
		repeat, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = io.ReadAll(repeat.Body)
		repeat.Body.Close()
		if repeat.StatusCode != 422 || !bytes.Contains(raw, []byte("document_known_unparseable")) || repeat.Header.Get("PAYMENT-RESPONSE") != "" || parseCalls.Load() != beforeParses+1 || len(store.rows) != beforeRows {
			t.Fatalf("known failure was parsed or charged: %d %s", repeat.StatusCode, raw)
		}
	})
}

func (s *nativeTestStore) Failed(_ context.Context, hash string, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now < s.failures[hash], nil
}
func (s *nativeTestStore) MarkFailed(_ context.Context, hash string, now int64) error {
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
