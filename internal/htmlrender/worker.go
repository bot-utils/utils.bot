package htmlrender

import (
	"context"
	"encoding/json"
	"time"

	"pdfservice/internal/htmllimits"
	"pdfservice/internal/jsonwire"
)

type Input struct {
	URL string `json:"url"`
}
type Worker struct {
	Load  func(context.Context) (DomainCheck, error)
	Fetch func(context.Context, string, DomainCheck) (Result, error)
}

// Invoke never returns a raw runtime error (Lambda would log it). It also
// contains panics without emitting values or a source-content stack trace.
func (w Worker) Invoke(ctx context.Context, payload []byte) (data []byte, invokeErr error) {
	defer func() {
		if recover() != nil {
			data = []byte(`{"error":"conversion_unavailable"}`)
			invokeErr = nil
		}
	}()
	var input Input
	if jsonwire.Decode(payload, &input, MaxRequest) != nil {
		return []byte(`{"error":"url_not_supported"}`), nil
	}
	if _, err := CanonicalURL(input.URL); err != nil {
		b, _ := json.Marshal(Result{Error: Code(err)})
		return b, nil
	}
	ctx, cancel := context.WithTimeout(ctx, htmllimits.HTMLWorkerSeconds*time.Second)
	defer cancel()
	var result Result
	domains, err := w.Load(ctx)
	if err == nil {
		if w.Fetch != nil {
			result, err = w.Fetch(ctx, input.URL, domains)
		} else {
			result, err = (Fetcher{Domains: domains}).Fetch(ctx, input.URL)
		}
	}
	if err != nil {
		result = Result{Error: Code(err)}
	}
	b, err := encodeResult(prepareResult(result))
	if err != nil {
		return []byte(`{"error":"conversion_unavailable"}`), nil
	}
	return b, nil
}
