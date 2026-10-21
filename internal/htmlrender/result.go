package htmlrender

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"pdfservice/internal/htmllimits"
	"pdfservice/internal/jsonwire"
)

func DecodeResult(wire []byte, input Input, javascript bool) (Result, error) {
	var result Result
	if jsonwire.Decode(wire, &result, MaxResult) != nil || !ValidateResult(result, input, javascript) {
		return Result{}, errors.New("invalid_worker_response")
	}
	if result.Error == "" {
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil || len(fields) != 8 {
			return Result{}, errors.New("invalid_worker_response")
		}
		for _, key := range []string{"url", "finalURL", "sourceStatus", "title", "markdown", "truncated", "javascript", "sourceBytes"} {
			value, present := fields[key]
			if !present || string(value) == "null" {
				return Result{}, errors.New("invalid_worker_response")
			}
		}
	}
	return result, nil
}

// A format boundary, not a prompt-injection detector. Never evaluate, render,
// interpolate into commands, or follow links from this untrusted source text.
func safeText(s string) bool {
	if !utf8.ValidString(s) || strings.ContainsAny(s, "<>") {
		return false
	}
	for _, r := range s {
		if forbiddenTextRune(r) {
			return false
		}
	}
	return true
}

func forbiddenTextRune(r rune) bool {
	return unicode.IsControl(r) && r != '\n' && r != '\t' || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}

func cleanText(s string, limit int) (string, bool) {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	s = strings.Map(func(r rune) rune {
		if forbiddenTextRune(r) {
			return -1
		}
		return r
	}, s)
	s = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(s)
	short := len(s) > limit
	if short {
		s = s[:limit]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s, short
}

func knownWorkerError(s string) bool {
	switch s {
	case ErrBlocked.Error(), ErrURL.Error(), ErrFetch.Error(), ErrType.Error(), ErrSize.Error(), ErrComplexity.Error(), ErrThreats.Error(), "conversion_unavailable":
		return true
	}
	return false
}

// ValidateResult is repeated outside the disposable VM before any settlement.
// Even a fully compromised worker may only return this bounded data schema.
func ValidateResult(r Result, input Input, javascript bool) bool {
	if r.Error != "" {
		return knownWorkerError(r.Error) && r.URL == "" && r.FinalURL == "" && r.Markdown == "" && r.Title == "" && r.SourceBytes == 0 && r.SourceStatus == 0 && !r.Truncated && !r.JavaScript
	}
	if r.URL != input.URL || r.JavaScript != javascript || r.SourceStatus < 200 || r.SourceStatus > 599 || r.SourceBytes < 0 || r.SourceBytes > MaxHTML || len(r.Title) > htmllimits.MaxHTMLTitle || len(r.Markdown) > MaxMarkdown || !safeText(r.Title) || !safeText(r.Markdown) {
		return false
	}
	u, err := CanonicalURL(r.FinalURL)
	return err == nil && u.String() == r.FinalURL
}

func prepareResult(r Result) Result {
	if r.Error != "" {
		if knownWorkerError(r.Error) {
			return Result{Error: r.Error}
		}
		return Result{Error: "conversion_unavailable"}
	}
	if !utf8.ValidString(r.Markdown) || !utf8.ValidString(r.Title) {
		return Result{Error: "conversion_unavailable"}
	}
	var short bool
	r.Markdown, short = cleanText(r.Markdown, MaxMarkdown)
	r.Truncated = r.Truncated || short
	r.Title, _ = cleanText(r.Title, htmllimits.MaxHTMLTitle)
	return r
}

// encodeResult preserves the longest UTF-8 prefix that fits the actual JSON
// budget, including both URLs, title, flags and JSON escaping. Never halve a
// customer's result just because it crosses the transport limit by one byte.
func encodeResult(r Result) ([]byte, error) {
	b, err := jsonwire.MarshalResponse(r)
	if err != nil || len(b) <= MaxResult {
		return b, err
	}
	r.Truncated = true
	text := r.Markdown
	r.Markdown = ""
	b, err = jsonwire.MarshalResponse(r)
	if err != nil || len(b) > MaxResult {
		return nil, errors.New("result_metadata_too_large")
	}
	// Search byte offsets; invalid UTF-8 suffixes are rounded down only when
	// selecting a candidate, keeping the search monotonic.
	// Changing false to true itself saves one JSON byte. If that alone
	// would fit, still remove a rune so truncated never falsely claims a cut.
	_, lastBytes := utf8.DecodeLastRuneInString(text)
	low, high := 0, len(text)-lastBytes
	for low < high {
		n := low + (high-low+1)/2
		end := n
		for end > 0 && !utf8.ValidString(text[:end]) {
			end--
		}
		r.Markdown = text[:end]
		candidate, e := jsonwire.MarshalResponse(r)
		if e != nil {
			return nil, e
		}
		if len(candidate) <= MaxResult {
			low = n
			b = candidate
		} else {
			high = n - 1
		}
	}
	return b, nil
}
