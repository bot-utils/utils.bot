package htmltool

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	x402 "github.com/x402-foundation/x402/go/v2"
	"pdfservice/internal/docs"
	"pdfservice/internal/htmllimits"
	"pdfservice/internal/htmlrender"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
)

func decodedALBBody(t *testing.T, out events.ALBTargetGroupResponse) []byte {
	t.Helper()
	body := []byte(out.Body)
	var err error
	if out.IsBase64Encoded {
		body, err = base64.StdEncoding.Strict().DecodeString(out.Body)
		if err != nil {
			t.Fatal(err)
		}
	}
	if values := out.MultiValueHeaders["Content-Encoding"]; len(values) == 1 && values[0] == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		body, err = io.ReadAll(io.LimitReader(reader, MaxResult+1))
		reader.Close()
		if err != nil || len(body) > MaxResult {
			t.Fatal("invalid compressed result", len(body), err)
		}
	}
	return body
}

func TestAcceptEncodingNegotiation(t *testing.T) {
	for _, tc := range []struct {
		value          string
		identity, gzip int
	}{
		{"", 1000, 0}, {", ,", 1000, 0}, {"gzip", 1000, 1000}, {"br, gzip;q=0.7", 1000, 700},
		{"GZIP;Q=0.001, identity;q=0", 0, 1}, {"*;q=0", 0, 0}, {"gzip, *;q=0", 0, 1000},
		{"*;q=1, gzip;q=0", 1000, 0}, {"identity;q=0, *;q=0.4", 0, 400}, {"gzip;q=1.000", 1000, 1000},
		{"gzip;q=0., identity;q=1.", 1000, 0}, {"gzip;q=0.5, gzip;q=0.500", 1000, 500},
	} {
		got, err := parseResponseEncoding(tc.value)
		if err != nil || got.identity != tc.identity || got.gzip != tc.gzip {
			t.Errorf("%q: %+v, %v", tc.value, got, err)
		}
	}
	for _, invalid := range []string{"gzip;q=NaN", "gzip;q=-1", "gzip;q=1.001", "gzip;q=.5", "gzip;q=0.0001", "gzip;q=1e0", "gzip;q=0.5;q=0.6", "gzip;level=1", "gzip;q=\"1\"", "gzip;q=1,gzip;q=0", "gz ip", ";q=1", "gzip;q=0..1"} {
		if _, err := parseResponseEncoding(invalid); err == nil {
			t.Errorf("invalid encoding accepted: %q", invalid)
		}
	}
}

func responseTestRequest(encoding string) []byte {
	event := events.ALBTargetGroupRequest{HTTPMethod: "POST", Path: Path, Headers: map[string]string{"host": "api.example.com", "content-type": "application/json", "payment-signature": "synthetic-unfunded-proof", "accept-encoding": encoding}, Body: `{"url":"https://example.com/"}`}
	wire, _ := json.Marshal(event)
	return wire
}

func randomResponseText(n int) string {
	r := rand.New(rand.NewPCG(1, 2))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Uint64()&63]
	}
	return string(b)
}

func TestControllerPreparesTransportBeforeSettlement(t *testing.T) {
	for _, tc := range []struct {
		name, encoding, text, code string
		status, settlements, works int
		compressed                 bool
	}{
		{"small plain", "", "hello", "", 200, 1, 1, false},
		{"small gzip optional", "gzip", "hello", "", 200, 1, 1, false},
		{"small gzip required", "gzip, identity;q=0", "hello", "", 200, 1, 1, true},
		{"large complete", "gzip", strings.Repeat("complete result 日本語\n", 110000) + "END", "", 200, 1, 1, true},
		{"large needs gzip", "", strings.Repeat("z", 2<<20), "gzip_required", 406, 0, 1, false},
		{"gzip explicitly refused", "*;q=1, gzip;q=0", strings.Repeat("z", 2<<20), "gzip_required", 406, 0, 1, false},
		{"incompressible", "gzip", randomResponseText(2 << 20), "response_size_limit", 422, 0, 1, false},
		{"all encodings refused", "gzip;q=0,identity;q=0", "hello", "", 406, 0, 0, false},
		{"malformed negotiation", "gzip;q=NaN", "hello", "invalid_accept_encoding", 400, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settlements, works := 0, 0
			cfg := protocol.Config{}.WithHTMLJavaScript(true)
			c := Controller{Config: cfg, Resource: "https://api.example.com" + Path,
				Pay: func(_ context.Context, request protocol.PaymentRequest) (protocol.PaymentResponse, error) {
					if request.DocumentFailed || request.RecordOutcome != "" {
						t.Fatal("transport failure counted as bad source")
					}
					if !request.VerifyOnly && !request.CheckDocument {
						settlements++
					}
					return protocol.PaymentResponse{Pass: true, Settlement: &x402.SettleResponse{Success: true, Network: x402.Network(cfg.Network()), Transaction: "0x" + strings.Repeat("a", 64), Payer: "0x" + strings.Repeat("b", 40), Amount: cfg.ForHTML().Requirements().Amount}}, nil
				}, Work: func(context.Context, Input) (Result, error) {
					works++
					return Result{URL: "https://example.com/", FinalURL: "https://example.com/", SourceStatus: 200, JavaScript: true, Markdown: tc.text}, nil
				}}
			wire, err := c.Invoke(context.Background(), responseTestRequest(tc.encoding))
			var response events.ALBTargetGroupResponse
			if err != nil || json.Unmarshal(wire, &response) != nil || response.StatusCode != tc.status || settlements != tc.settlements || works != tc.works || len(wire) > htmllimits.ALBMaxResponse {
				t.Fatalf("status=%d settlements=%d works=%d envelope=%d err=%v", response.StatusCode, settlements, works, len(wire), err)
			}
			body := decodedALBBody(t, response)
			compressed := len(response.MultiValueHeaders["Content-Encoding"]) != 0
			if compressed != tc.compressed || strings.Join(response.MultiValueHeaders["Vary"], ",") != "Accept-Encoding" {
				t.Fatal("wrong transport headers", response.MultiValueHeaders)
			}
			if response.StatusCode == 200 {
				var result Result
				if json.Unmarshal(body, &result) != nil || result.Markdown != tc.text || result.Truncated || len(response.MultiValueHeaders["PAYMENT-RESPONSE"]) != 1 {
					t.Fatal("result or receipt lost")
				}
			} else if tc.code != "" && (!bytes.Contains(body, []byte(tc.code)) || len(response.MultiValueHeaders["PAYMENT-RESPONSE"]) != 0) {
				t.Fatal("bad error or unexpected payment receipt", string(body))
			}
		})
	}
}

func TestResponseEnvelopeAndReceiptBound(t *testing.T) {
	for _, mode := range []string{protocol.ModeMock, protocol.ModeBase, protocol.ModeSepolia} {
		address := "0x" + strings.Repeat("2", 40)
		if mode == protocol.ModeMock {
			address = ""
		}
		cfg, err := protocol.NewConfig(mode, address)
		if err != nil {
			t.Fatal(err)
		}
		cfg = cfg.ForHTML()
		maximum := maximumSettlementReceipt(cfg)
		for _, amount := range []string{"", cfg.Requirements().Amount} {
			s := &x402.SettleResponse{Success: true, Network: x402.Network(cfg.Network()), Transaction: "0x" + strings.Repeat("a", 64), Payer: "0x" + strings.Repeat("b", 40), Amount: amount}
			actual, _ := protocol.Header(cfg.SettlementEvidence(s))
			if !cfg.ValidSettlement(s) || len(actual) > len(maximum) {
				t.Fatal("receipt exceeds preflight reservation")
			}
		}
	}
	base := events.ALBTargetGroupResponse{MultiValueHeaders: map[string][]string{"Content-Type": {"application/json"}, "PAYMENT-RESPONSE": {maximumSettlementReceipt(protocol.Config{}.ForHTML())}}}
	for _, text := range []string{strings.Repeat("a", 1000000), strings.Repeat(`"\&`, 200000), strings.Repeat("日", 300000)} {
		body, _ := jsonwire.MarshalResponse(map[string]string{"markdown": text})
		out, err := encodeALBResponse(base, 200, body, responseEncoding{identity: 1000, gzip: 1000})
		wire, _ := json.Marshal(out)
		if err != nil || len(wire) > htmllimits.ALBMaxResponse || !bytes.Equal(decodedALBBody(t, out), body) || len(base.MultiValueHeaders["Content-Encoding"]) != 0 {
			t.Fatal("envelope overflow, mutation or round-trip failure", len(wire), err)
		}
	}
	var bounded compressedBuffer
	if _, err := bounded.Write(make([]byte, htmllimits.MaxCompressedBody+1)); err == nil || bounded.Len() != 0 {
		t.Fatal("compression buffer exceeded bound")
	}
}

func TestOrdinaryHTTPClientAutomaticallyDecodesGzip(t *testing.T) {
	text := strings.Repeat("A complete large response.\n", 120000)
	body, _ := jsonwire.MarshalResponse(map[string]string{"markdown": text})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc, err := parseResponseEncoding(r.Header.Get("Accept-Encoding"))
		if err != nil || enc.gzip == 0 {
			t.Error("client did not advertise gzip")
			w.WriteHeader(400)
			return
		}
		out, err := encodeALBResponse(events.ALBTargetGroupResponse{MultiValueHeaders: map[string][]string{"Content-Type": {"application/json"}}}, 200, body, enc)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		for key, values := range out.MultiValueHeaders {
			w.Header()[key] = values
		}
		// Simulate only ALB's documented internal base64 decoding. The client
		// receives compressed bytes and performs standard HTTP decompression.
		encoded, err := base64.StdEncoding.DecodeString(out.Body)
		if err != nil || !out.IsBase64Encoded {
			t.Error("invalid internal gzip transport", err)
			w.WriteHeader(500)
			return
		}
		w.Write(encoded)
	}))
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	decoded, err := io.ReadAll(io.LimitReader(response.Body, MaxResult+1))
	if err != nil || !response.Uncompressed || !bytes.Equal(decoded, body) {
		t.Fatal("client needed custom decoding or lost content", err)
	}
}

func FuzzResponseEncoding(f *testing.F) {
	for _, seed := range []string{"", "gzip", "gzip;q=0,*;q=1", "identity;q=0", "gzip;q=1e0"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1024 {
			return
		}
		enc, err := parseResponseEncoding(raw)
		if err == nil && (enc.identity < 0 || enc.identity > 1000 || enc.gzip < 0 || enc.gzip > 1000) {
			t.Fatal("quality escaped bounds")
		}
	})
}

func TestCompressionRepresentativeConversions(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	page := httptest.NewRecorder()
	docs.New(protocol.APIOrigin+"/v1/pdf/text").ServeHTTP(page, httptest.NewRequest("GET", "/", nil))
	entropy := randomResponseText(1000000)
	var entropyHTML strings.Builder
	for i := 0; i < len(entropy); i += 10000 {
		entropyHTML.WriteString("<p>" + entropy[i:i+10000] + "</p>")
	}
	fixtures := map[string]string{
		"homepage":        page.Body.String(),
		"generated-dom":   "<body>" + strings.Repeat("<p>"+strings.Repeat("large-fixture ", 80)+"</p>", 2600) + "<p>END</p></body>",
		"reference-table": "<table>" + strings.Repeat("<tr><td>Reference section: Unicode 日本語, punctuation and identifiers</td><td>0123456789 value</td></tr>", 18000) + "</table>",
		"high-entropy":    "<body>" + entropyHTML.String() + "</body>",
	}
	for name, source := range fixtures {
		t.Run(name, func(t *testing.T) {
			markdown, title, partial, err := htmlrender.Convert(context.Background(), []byte(source), base)
			if err != nil || partial {
				t.Fatal("conversion fixture failed", partial, err)
			}
			result := Result{URL: base.String(), FinalURL: base.String(), SourceStatus: 200, Title: title, Markdown: markdown}
			body, _ := jsonwire.MarshalResponse(result)
			start := time.Now()
			out, err := encodeALBResponse(events.ALBTargetGroupResponse{MultiValueHeaders: map[string][]string{"Content-Type": {"application/json"}}}, 200, body, responseEncoding{identity: 1000, gzip: 1000})
			elapsed := time.Since(start)
			wire, _ := json.Marshal(out)
			if err != nil || !bytes.Equal(decodedALBBody(t, out), body) {
				t.Fatal("compression failed", err)
			}
			if name == "generated-dom" && (!strings.HasSuffix(markdown, "END") || len(body) <= htmllimits.MaxCompressedBody) {
				t.Fatal("large fixture not complete")
			}
			t.Logf("source=%d markdown=%d json=%d ALB-envelope=%d encode=%s partial=%t", len(source), len(markdown), len(body), len(wire), elapsed, partial)
		})
	}
}
