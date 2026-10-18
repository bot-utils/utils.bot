package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
)

func regionalTestServer(t *testing.T) http.Handler {
	t.Helper()
	return New(protocol.APIOrigin+"/v1/pdf/text", func(context.Context, protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		t.Fatal("payment invoked")
		return protocol.PaymentResponse{}, nil
	}, func(context.Context, []byte) (parser.Result, error) {
		t.Fatal("parser invoked")
		return parser.Result{}, nil
	}).Handler()
}
func TestRegionalSwaggerPreflightAndUnpaidQuote(t *testing.T) {
	h := regionalTestServer(t)
	for _, method := range []string{"OPTIONS", "POST"} {
		r := httptest.NewRequest(method, "/v1/pdf/text", nil)
		r.Header.Set("Origin", protocol.SiteOrigin)
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "content-type, PAYMENT-SIGNATURE")
		r.Body = unreadableBody{t: t}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 204
		if method == "POST" {
			want = 402
		}
		if w.Code != want || w.Header().Get("Access-Control-Allow-Origin") != protocol.SiteOrigin || w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %v", method, w.Code, w.Header())
		}
		if method == "POST" && (!strings.Contains(w.Body.String(), protocol.APIOrigin+"/v1/pdf/text") || !strings.Contains(w.Header().Get("Link"), protocol.SiteOrigin+"/openapi") || w.Header().Get("PAYMENT-REQUIRED") == "") {
			t.Fatal("wrong regional quote", w.Body.String())
		}
	}
}
func TestRegionalPreflightRejectsUntrustedOriginsHeadersAndBodies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*http.Request)
		status int
	}{
		{"foreign", func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 403},
		{"missing", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"duplicate", func(r *http.Request) { r.Header.Add("Origin", protocol.SiteOrigin) }, 403},
		{"method", func(r *http.Request) { r.Header.Set("Access-Control-Request-Method", "PUT") }, 400},
		{"headers", func(r *http.Request) { r.Header.Set("Access-Control-Request-Headers", "X-Agent-Pdf-Origin") }, 400},
		{"duplicateHeaders", func(r *http.Request) { r.Header.Add("Access-Control-Request-Headers", "content-type") }, 400},
		{"body", func(r *http.Request) { r.ContentLength = 1 }, 400},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		{"query", func(r *http.Request) { r.URL.RawQuery = "a=1" }, 400},
		{"range", func(r *http.Request) { r.Header.Set("Range", "bytes=0-0") }, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("OPTIONS", "/v1/pdf/text", nil)
			r.Header.Set("Origin", protocol.SiteOrigin)
			r.Header.Set("Access-Control-Request-Method", "POST")
			r.Header.Set("Access-Control-Request-Headers", "content-type")
			r.Body = unreadableBody{t: t}
			tc.edit(r)
			w := httptest.NewRecorder()
			regionalTestServer(t).ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Access-Control-Allow-Methods") != "" {
				t.Fatal(w.Code, w.Header(), w.Body.String())
			}
		})
	}
}
func TestRegionalServerToServerUnpaidRequestDoesNotRequireOrigin(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/pdf/text", nil)
	r.Body = unreadableBody{t: t}
	w := httptest.NewRecorder()
	regionalTestServer(t).ServeHTTP(w, r)
	if w.Code != 402 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal(w.Code, w.Header())
	}
}
