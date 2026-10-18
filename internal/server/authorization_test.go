package server

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"pdfservice/internal/parser"
	"pdfservice/internal/protocol"
)

func TestDisclosedPartialResultIsChargedAndMarkedInJSON(t *testing.T) {
	for _, limit := range []string{"pages", "text"} {
		t.Run(limit, func(t *testing.T) {
			settlements := 0
			result := parser.Result{PageCount: 101, Truncated: true, Pages: []parser.Page{{Index: 0, Text: "bounded extracted text"}}}
			if limit == "text" {
				result.PageCount = 1
				result.Pages[0].Text = strings.Repeat("a", protocol.MaxText)
			}
			s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				if r.VerifyOnly || r.CheckDocument {
					return protocol.PaymentResponse{Pass: true}, nil
				}
				if r.DocumentFailed {
					t.Fatal("partial success marked as a failed PDF")
				}
				settlements++
				return validApproval(), nil
			}, func(context.Context, []byte) (parser.Result, error) { return result, nil })
			r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("document"))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var out parser.Result
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || settlements != 1 || !out.Truncated || out.PageCount != result.PageCount || w.Header().Get("PAYMENT-RESPONSE") == "" {
				t.Fatalf("partial result not charged/disclosed: status=%d settlements=%d", w.Code, settlements)
			}
		})
	}
}

func TestAuthorizationOrdersCheckParseEncodeSettlementAndDelivery(t *testing.T) {
	for _, outcome := range []string{"success", "document", "service", "encoding", "payment-failure", "known-failure", "binding-mismatch"} {
		t.Run(outcome, func(t *testing.T) {
			var events []string
			s := New("http://example.test/v1/pdf/text", func(_ context.Context, req protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				switch {
				case req.VerifyOnly:
					events = append(events, "verify")
					return protocol.PaymentResponse{Pass: true}, nil
				case req.CheckDocument:
					events = append(events, "check")
					if req.BodySHA256 != protocol.SHA256([]byte("document")) || req.BodyLength != 8 {
						t.Fatal("wrong document lookup")
					}
					if outcome == "known-failure" {
						return protocol.PaymentResponse{Status: 422, Error: "document_known_unparseable"}, nil
					}
					if outcome == "binding-mismatch" {
						return protocol.PaymentResponse{Status: 409, Error: "payment_document_mismatch"}, nil
					}
					return protocol.PaymentResponse{Pass: true}, nil
				case req.DocumentFailed:
					events = append(events, "mark-failure")
					return protocol.PaymentResponse{Pass: true}, nil
				default:
					events = append(events, "settle")
					if outcome == "payment-failure" {
						return protocol.PaymentResponse{Status: 502, Error: "payment_unavailable"}, nil
					}
					return validApproval(), nil
				}
			}, func(context.Context, []byte) (parser.Result, error) {
				events = append(events, "parse")
				result := parser.Result{PageCount: 1, Pages: []parser.Page{{Text: "private extracted result"}}}
				switch outcome {
				case "document":
					return parser.Result{Attempts: []parser.Attempt{{Engine: "pdfium", Outcome: "document_error"}, {Engine: "poppler", Outcome: "document_error"}}}, parser.ErrDocument
				case "service":
					return result, parser.ErrSetup
				case "encoding":
					result.Pages[0].Width = math.NaN()
				}
				return result, nil
			})
			r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("document"))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			want := []string{"verify", "check", "parse"}
			status := 502
			switch outcome {
			case "success":
				want = append(want, "settle")
				status = 200
			case "payment-failure":
				want = append(want, "settle")
			case "document":
				want = append(want, "mark-failure")
				status = 422
			case "known-failure":
				want = want[:2]
				status = 422
			case "binding-mismatch":
				want = want[:2]
				status = 409
			}
			if !reflect.DeepEqual(events, want) || w.Code != status {
				t.Fatalf("events=%v status=%d", events, w.Code)
			}
			if outcome != "success" && strings.Contains(w.Body.String(), "private extracted result") {
				t.Fatal("result leaked without successful payment")
			}
			if outcome != "success" && w.Header().Get("PAYMENT-RESPONSE") != "" {
				t.Fatal("uncharged failure advertised settlement")
			}
		})
	}
}

func TestServiceOrInvalidWorkerOutputNeverPoisonsDocumentCache(t *testing.T) {
	for _, outcome := range []string{"invalid_output", "setup_failed", "success", "no_text"} {
		if cacheableFailure(parser.Result{Attempts: []parser.Attempt{{Outcome: outcome}}}) {
			t.Fatal("unsafe failure evidence cached", outcome)
		}
	}
	if cacheableFailure(parser.Result{}) {
		t.Fatal("missing evidence cached")
	}
}

func TestFailedCollectionDoesNotReturnParseOutputAndReleasesCapacity(t *testing.T) {
	s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
		if r.VerifyOnly || r.CheckDocument {
			return protocol.PaymentResponse{Pass: true}, nil
		}
		return protocol.PaymentResponse{}, errors.New("provider transport failed")
	}, func(context.Context, []byte) (parser.Result, error) {
		return parser.Result{Pages: []parser.Page{{Text: "secret parsed text"}}}, nil
	})
	r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader("document"))
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("PAYMENT-SIGNATURE", "fixture")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret parsed text") || len(s.Slots) != 0 {
		t.Fatal("failed collection leaked output or capacity")
	}
}

func TestSuccessfulBlankDocumentCollectsPaymentButEmptyUploadDoesNot(t *testing.T) {
	for _, body := range []string{"blank PDF bytes", ""} {
		t.Run(body, func(t *testing.T) {
			var parses, settlements int
			s := New("http://example.test/v1/pdf/text", func(_ context.Context, r protocol.PaymentRequest) (protocol.PaymentResponse, error) {
				if r.VerifyOnly || r.CheckDocument {
					return protocol.PaymentResponse{Pass: true}, nil
				}
				if r.DocumentFailed {
					t.Fatal("blank success cached as a document failure")
				}
				settlements++
				return validApproval(), nil
			}, func(context.Context, []byte) (parser.Result, error) {
				parses++
				return parser.Result{PageCount: 1, Pages: []parser.Page{{Index: 0, Width: 612, Height: 792, Text: ""}}, Warnings: []string{"no_extractable_text"}}, nil
			})
			r := httptest.NewRequest("POST", "/v1/pdf/text", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/pdf")
			r.Header.Set("PAYMENT-SIGNATURE", "fixture")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if body == "" {
				if w.Code != 400 || parses != 0 || settlements != 0 || w.Header().Get("PAYMENT-RESPONSE") != "" {
					t.Fatal("empty upload was processed or charged")
				}
			} else if w.Code != 200 || parses != 1 || settlements != 1 || w.Header().Get("PAYMENT-RESPONSE") == "" || !strings.Contains(w.Body.String(), "no_extractable_text") {
				t.Fatal("blank result was not returned as a paid successful parse")
			}
		})
	}
}
