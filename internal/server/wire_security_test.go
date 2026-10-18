package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pdfservice/internal/protocol"
)

// Exercise the real HTTP parser and response finalization, not just a recorder.
// A client advertises a large/incomplete body but never sends it. Refusals must
// arrive without waiting for the body and must not admit a pipelined request.
func TestWireRefusalsDoNotWaitForOrReuseUntrustedUpload(t *testing.T) {
	var paymentCalls atomic.Int64
	s := New("https://utils.bot/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		paymentCalls.Add(1)
		return protocol.PaymentResponse{}, nil
	}, nil)
	server := httptest.NewUnstartedServer(s.Handler())
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.ErrorLog = nil
	server.Start()
	defer server.Close()
	for _, test := range []struct {
		name, request string
		status        int
	}{
		{"unpaid", "POST /v1/pdf/text HTTP/1.1\r\nHost: example.test\r\nContent-Length: 104857600\r\n\r\n", 402},
		{"unsupported-path", "POST /v100/words HTTP/1.1\r\nHost: example.test\r\nContent-Length: 104857600\r\n\r\n", 404},
		{"unsupported-method", "PUT /v1/pdf/text HTTP/1.1\r\nHost: example.test\r\nContent-Length: 104857600\r\n\r\n", 405},
		{"content-type", "POST /v1/pdf/text HTTP/1.1\r\nHost: example.test\r\nPayment-Signature: fixture\r\nContent-Type: text/plain\r\nContent-Length: 104857600\r\n\r\n", 415},
		{"ambiguous-length", "POST /v1/pdf/text HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 9\r\n\r\n", 400},
		{"unpaid-chunked-with-length", "POST /v1/pdf/text HTTP/1.1\r\nHost: example.test\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n", 402},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			// The following bytes are not the advertised PDF/chunks. Even if the
			// first refusal succeeds, they must never become a second request.
			if _, err := io.WriteString(connection, test.request+"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(connection)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatalf("refusal waited for upload: %v", err)
			}
			if response.StatusCode != test.status || !response.Close {
				t.Fatalf("status=%d closed=%t", response.StatusCode, response.Close)
			}
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if next, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet}); err == nil {
				_ = next.Body.Close()
				t.Fatal("untrusted upload bytes became another request")
			}
		})
	}
	if paymentCalls.Load() != 0 {
		t.Fatal("transport refusals invoked payment")
	}
	response, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatal("healthy client blocked after malformed traffic", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || !strings.Contains(string(data), `"ready"`) {
		t.Fatal("healthy request failed after transport probes")
	}
}
