package csvcloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type privateDrainHTTP struct {
	do     func(*http.Request) (*http.Response, error)
	closed int
}

func (c *privateDrainHTTP) Do(r *http.Request) (*http.Response, error) { return c.do(r) }
func (c *privateDrainHTTP) CloseIdleConnections()                      { c.closed++ }

func TestConfirmedAdmissionReplayRetriesOnlyExplicitDraining(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures int
		marked   bool
		code     string
		calls    int
		success  bool
	}{
		{"one drain", 1, true, "draining", 2, true},
		{"generic unavailable", 1, true, "unavailable", 1, false},
		{"unmarked drain", 1, false, "draining", 1, false},
		{"bounded drains", 9, true, "draining", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			known := PrivateAdmission{JobID: ID(), Expires: time.Now().Add(time.Minute).Unix(), PaymentMode: "synthetic-no-funds", Parts: []PrivatePart{{Slot: "file", Number: 1}}}
			calls := 0
			var firstBody string
			client := &privateDrainHTTP{}
			client.do = func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.String() != "https://api.utils.bot/csv/dedupe" {
					t.Fatal("unexpected effect")
				}
				b, _ := io.ReadAll(r.Body)
				if calls == 1 {
					firstBody = string(b)
				} else if string(b) != firstBody {
					t.Fatal("replay body changed")
				}
				status := 201
				header := http.Header{}
				header.Set("X-CSV-Payment-Mode", "synthetic-no-funds")
				body, _ := json.Marshal(known)
				if calls <= tc.failures {
					status = 503
					body = []byte(`{"error":"` + tc.code + `"}`)
					if tc.marked {
						header.Set("Retry-After", "1")
					}
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			}
			a := privateAPIClient{HTTP: client, Key: ID()}
			var out PrivateAdmission
			err := a.confirmedAdmissionReplay(context.Background(), "/csv/dedupe", map[string]string{"delivery": "gzip"}, known, &out)
			if (err == nil) != tc.success || calls != tc.calls || client.closed != tc.calls-1 {
				t.Fatal("retry contract violated", calls, client.closed, err)
			}
			if tc.success && out.JobID != known.JobID {
				t.Fatal("binding changed")
			}
		})
	}
}

func TestFirstAdmissionDrainIsNeverRetried(t *testing.T) {
	fixture, err := privateSmallFixture("dedupe")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client := &privateDrainHTTP{do: func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": {"1"}}, Body: io.NopCloser(strings.NewReader(`{"error":"draining"}`))}, nil
	}}
	a := privateAPIClient{HTTP: client, Key: ID()}
	if _, err = a.admit(context.Background(), ID(), fixture, Storage{}); err == nil || calls != 1 || client.closed != 0 {
		t.Fatal("first admission retried", calls, err)
	}
	var replay PrivateAdmission
	if a.confirmedAdmissionReplay(context.Background(), "/csv/dedupe", nil, PrivateAdmission{}, &replay) != ErrInvalid || calls != 1 {
		t.Fatal("unconfirmed replay allowed")
	}
}
