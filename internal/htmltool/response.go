package htmltool

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"pdfservice/internal/htmllimits"
	"pdfservice/internal/protocol"
)

var errResponseSize = errors.New("response_size_limit")
var errGzipRequired = errors.New("gzip_required")
var errAcceptEncoding = errors.New("invalid_accept_encoding")

// Qualities use integers to avoid accepting NaN, exponents or invalid qvalues.
type responseEncoding struct{ identity, gzip int }

func parseResponseEncoding(value string) (responseEncoding, error) {
	qualities := map[string]int{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" { // HTTP list syntax permits empty members.
			continue
		}
		name, parameter, hasParameter := strings.Cut(item, ";")
		name = strings.ToLower(strings.TrimSpace(name))
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return responseEncoding{}, errAcceptEncoding
			}
		}
		if name == "" {
			return responseEncoding{}, errAcceptEncoding
		}
		q := 1000
		if hasParameter {
			key, raw, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				return responseEncoding{}, errAcceptEncoding
			}
			var valid bool
			q, valid = encodingQuality(strings.TrimSpace(raw))
			if !valid {
				return responseEncoding{}, errAcceptEncoding
			}
		}
		if prior, duplicate := qualities[name]; duplicate && prior != q {
			return responseEncoding{}, errAcceptEncoding
		}
		qualities[name] = q
	}
	enc := responseEncoding{identity: 1000}
	if q, ok := qualities["identity"]; ok {
		enc.identity = q
	} else if q, ok := qualities["*"]; ok && q == 0 {
		enc.identity = 0
	}
	if q, ok := qualities["gzip"]; ok {
		enc.gzip = q
	} else {
		enc.gzip = qualities["*"]
	}
	return enc, nil
}

func encodingQuality(s string) (int, bool) {
	whole, fraction, point := strings.Cut(s, ".")
	if whole != "0" && whole != "1" || len(fraction) > 3 || !point && fraction != "" {
		return 0, false
	}
	q := 0
	for _, c := range fraction {
		if c < '0' || c > '9' || whole == "1" && c != '0' {
			return 0, false
		}
		q = q*10 + int(c-'0')
	}
	if whole == "1" {
		return 1000, true
	}
	for range 3 - len(fraction) {
		q *= 10
	}
	return q, true
}

type compressedBuffer struct{ bytes.Buffer }

func (b *compressedBuffer) Write(p []byte) (int, error) {
	if len(p) > htmllimits.MaxCompressedBody-b.Len() {
		return 0, errResponseSize
	}
	return b.Buffer.Write(p)
}

// encodeALBResponse never changes the JSON result. Identity may use raw text or
// internal base64, whichever creates the smaller envelope; ALB decodes base64.
// Gzip is per-response, deterministic, bounded and contains no payment headers.
func encodeALBResponse(base events.ALBTargetGroupResponse, status int, body []byte, enc responseEncoding) (events.ALBTargetGroupResponse, error) {
	out := base
	out.StatusCode = status
	out.StatusDescription = strconv.Itoa(status) + " " + http.StatusText(status)
	out.MultiValueHeaders = maps.Clone(base.MultiValueHeaders)
	out.MultiValueHeaders["Vary"] = []string{"Accept-Encoding"}
	delete(out.MultiValueHeaders, "Content-Encoding")
	var identity events.ALBTargetGroupResponse
	identitySize := 0
	if enc.identity > 0 && len(body) < htmllimits.ALBMaxResponse {
		for _, binary := range []bool{false, true} {
			candidate := out
			candidate.Body = string(body)
			candidate.IsBase64Encoded = binary
			if binary {
				candidate.Body = base64.StdEncoding.EncodeToString(body)
			}
			wire, err := json.Marshal(candidate)
			if err == nil && len(wire) <= htmllimits.ALBMaxResponse && (identitySize == 0 || len(wire) < identitySize) {
				identity, identitySize = candidate, len(wire)
			}
		}
	}
	if identitySize != 0 && (enc.gzip == 0 || len(body) < 1024 && enc.identity >= enc.gzip || enc.identity > enc.gzip) {
		return identity, nil
	}
	if enc.gzip > 0 {
		var compressed compressedBuffer
		writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
		if err == nil {
			_, err = writer.Write(body)
			closeErr := writer.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err == nil {
			candidate := out
			candidate.MultiValueHeaders = maps.Clone(out.MultiValueHeaders)
			candidate.MultiValueHeaders["Content-Encoding"] = []string{"gzip"}
			candidate.IsBase64Encoded = true
			candidate.Body = base64.StdEncoding.EncodeToString(compressed.Bytes())
			wire, marshalErr := json.Marshal(candidate)
			if marshalErr == nil && len(wire) <= htmllimits.ALBMaxResponse && (identitySize == 0 || len(wire) < identitySize || enc.gzip > enc.identity) {
				return candidate, nil
			}
		}
	}
	if identitySize != 0 {
		return identity, nil
	}
	if enc.gzip == 0 && enc.identity > 0 {
		return events.ALBTargetGroupResponse{}, errGzipRequired
	}
	return events.ALBTargetGroupResponse{}, errResponseSize
}

// The real receipt is bounded by ValidSettlement/SettlementEvidence. Reserve
// its longest valid shape before settlement, and reuse the prepared body after
// payment so compression/serialization cannot newly reject a paid result.
func maximumSettlementReceipt(cfg protocol.Config) string {
	receipt, _ := protocol.Header(map[string]any{"success": true, "network": cfg.Network(), "payer": "0x" + strings.Repeat("f", 40), "transaction": "0x" + strings.Repeat("f", 64), "amount": cfg.Requirements().Amount})
	return receipt
}
