package csvcloud

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func networkFixture() (NetworkBinding, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	return NetworkBinding{RunID: ID(), JobID: ID(), TaskARN: "arn:aws:ecs:us-east-2:123456789012:task/utils-bot-csv-trial/" + strings.Repeat("a", 32), Nonce: ID(), Interfaces: []string{"eni-0123456789abcdef0"}, Issued: fixtureTime.Unix(), Expires: fixtureTime.Add(30 * time.Second).Unix()}, pub, key
}

type absentStub struct {
	err   error
	calls int
}

func (a *absentStub) VerifyAbsent(context.Context, []string) error { a.calls++; return a.err }
func TestIndependentVerifierRequiresExactNotFoundAndNoRetries(t *testing.T) {
	for _, scenario := range []string{"absent", "empty200", "present", "denied", "timeout", "malformed", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			reader, e := NewEC2Reader(sdkConfig(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.String() != "https://ec2.us-east-2.amazonaws.com/" || !strings.Contains(req.Header.Get("Authorization"), "ec2/aws4_request") {
					t.Fatal("unsigned or foreign endpoint")
				}
				if req.ParseForm() != nil || req.Form.Get("Action") != "DescribeNetworkInterfaces" || req.Form.Get("NetworkInterfaceId.1") != "eni-0123456789abcdef0" || req.Form.Get("NetworkInterfaceId.2") != "" {
					t.Fatal("unbounded interface request")
				}
				switch scenario {
				case "absent":
					return response(400, `<Response><Errors><Error><Code>InvalidNetworkInterfaceID.NotFound</Code></Error></Errors></Response>`, nil), nil
				case "denied":
					return response(403, `<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>`, nil), nil
				case "timeout":
					return nil, context.DeadlineExceeded
				case "truncated":
					return response(400, strings.Repeat("x", (64<<10)+1), nil), nil
				case "malformed":
					return response(400, `<Response><Errors>`, nil), nil
				default:
					return response(200, `<DescribeNetworkInterfacesResponse><networkInterfaceSet/></DescribeNetworkInterfacesResponse>`, nil), nil
				}
			}))
			if e != nil {
				t.Fatal(e)
			}
			e = reader.VerifyAbsent(ctx, []string{"eni-0123456789abcdef0"})
			if (e == nil) != (scenario == "absent") || calls != 1 {
				t.Fatal("ambiguous absence or retry", e, calls)
			}
			if reader.VerifyAbsent(ctx, []string{"eni-0123456789abcdef0", "eni-0123456789abcdef1"}) == nil || calls != 1 {
				t.Fatal("multi-ID notfound could hide live interface")
			}
		})
	}
}
func TestNetworkProofRejectsForeignStaleContradictoryEvidence(t *testing.T) {
	b, pub, key := networkFixture()
	reader := &absentStub{}
	observe := func(context.Context) (string, []string, error) { return b.TaskARN, b.Interfaces, nil }
	proof, e := SignNetworkProof(ctx, b, key, observe, reader, fixtureTime)
	if e != nil || VerifyNetworkProof(proof, b, pub, fixtureTime) != nil {
		t.Fatal("proof fixture", e)
	}
	for _, scenario := range []string{"nonce", "run", "job", "task", "eni", "expired", "future", "signature"} {
		t.Run(scenario, func(t *testing.T) {
			bad := b
			now := fixtureTime
			p := proof
			switch scenario {
			case "nonce":
				bad.Nonce = ID()
			case "run":
				bad.RunID = ID()
			case "job":
				bad.JobID = ID()
			case "task":
				bad.TaskARN += "x"
			case "eni":
				bad.Interfaces = []string{"eni-0123456789abcdef1"}
			case "expired":
				now = fixtureTime.Add(30 * time.Second)
			case "future":
				now = fixtureTime.Add(-time.Second)
			case "signature":
				p.Signature = "invalid"
			}
			if VerifyNetworkProof(p, bad, pub, now) == nil {
				t.Fatal("foreign/stale evidence accepted")
			}
		})
	}
	reader.err = ErrCleanup
	if _, e = SignNetworkProof(ctx, b, key, observe, reader, fixtureTime); e == nil {
		t.Fatal("signed live network")
	}
}
func TestNetworkChannelDeliversOnlyAuthenticatedCurrentNonce(t *testing.T) {
	b, pub, key := networkFixture()
	repo, _ := memoryRepo()
	channel := NetworkChannel{Repo: repo, RunID: b.RunID, JobID: b.JobID, TaskARN: b.TaskARN, PublicKey: pub, Now: func() time.Time { return fixtureTime }}
	operation, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- channel.VerifyAbsent(operation, b.Interfaces) }()
	var pending NetworkBinding
	for {
		var e error
		pending, e = channel.Pending(operation)
		if e == nil {
			break
		}
		select {
		case <-operation.Done():
			t.Fatal("request not stored")
		case <-time.After(time.Millisecond):
		}
	}
	proof, e := SignNetworkProof(ctx, pending, key, func(context.Context) (string, []string, error) { return pending.TaskARN, pending.Interfaces, nil }, &absentStub{}, fixtureTime)
	if e != nil {
		t.Fatal(e)
	}
	bad := proof
	bad.Binding.Nonce = ID()
	if channel.Deliver(ctx, bad) == nil {
		t.Fatal("foreign nonce delivered")
	}
	if channel.Deliver(ctx, proof) != nil {
		t.Fatal("proof not delivered")
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if channel.Deliver(ctx, proof) == nil {
		t.Fatal("proof overwrite/replay allowed")
	}
	raw, _ := json.Marshal(proof)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("private signing material persisted")
	}
}
func TestStoppedObserverIndependentlyRejectsRunningAndForeignTask(t *testing.T) {
	w, dispatch, ecs, _ := workerFixture()
	observer := StoppedObserver{Client: ecs, Cluster: w.Cluster, TaskARN: dispatch.TaskARN, Definition: w.Definition, Group: "csv-" + dispatch.Token, StartedBy: dispatch.Token[:32]}
	if _, _, e := observer.Observe(ctx); e == nil {
		t.Fatal("running task accepted")
	}
	ecs.task.LastStatus = ptrStopped()
	if _, ids, e := observer.Observe(ctx); e != nil || len(ids) != 1 {
		t.Fatal("stopped observation", e)
	}
	observer.Group = "foreign"
	if _, _, e := observer.Observe(ctx); e == nil {
		t.Fatal("foreign task accepted")
	}
}
func ptrStopped() *string { s := "STOPPED"; return &s }
