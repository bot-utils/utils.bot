package csvcloud

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func privateConfigFixture(t *testing.T) PrivateAPIConfig {
	t.Helper()
	f := newPrivateBackendFixture(t)
	return PrivateAPIConfig{Account: "999999999999", SyntheticOnly: true, AllowedIP: "192.0.2.10", KeySHA256: ID(), ALBPeers: []string{"10.0.0.0/24", "10.0.1.0/24"}, Runs: []PrivateAPIRun{{ID: f.b.RunID, Until: fixtureTime.Add(time.Hour).Unix(), Request: f.b.Request}}}
}
func TestPrivateAPIConfigRequiresBoundedSyntheticFixtures(t *testing.T) {
	for _, scenario := range []string{"valid", "account", "public", "key", "private_owner", "broad_peer", "public_peer", "host_peer", "duplicate_run", "duplicate_binding", "future_deadline", "unknown_field", "duplicate_field"} {
		t.Run(scenario, func(t *testing.T) {
			c := privateConfigFixture(t)
			switch scenario {
			case "account":
				c.Account = "123456789012"
			case "public":
				c.SyntheticOnly = false
			case "key":
				c.KeySHA256 = "secret"
			case "private_owner":
				c.AllowedIP = "10.1.1.1"
			case "broad_peer":
				c.ALBPeers = []string{"10.0.0.0/8"}
			case "public_peer":
				c.ALBPeers = []string{"192.0.2.0/24"}
			case "host_peer":
				c.ALBPeers = []string{"10.0.0.1/24"}
			case "duplicate_run":
				c.Runs = append(c.Runs, c.Runs[0])
			case "duplicate_binding":
				second := c.Runs[0]
				second.ID = ID()
				c.Runs = append(c.Runs, second)
			case "future_deadline":
				c.Runs[0].Until = fixtureTime.Add(2*time.Hour + time.Second).Unix()
			}
			raw, _ := json.Marshal(c)
			if scenario == "unknown_field" {
				raw = append(raw[:len(raw)-1], []byte(`,"instructions":"run code"}`)...)
			}
			if scenario == "duplicate_field" {
				raw = append(raw[:len(raw)-1], []byte(`,"synthetic_only":true}`)...)
			}
			_, err := ParsePrivateAPIConfig(raw, fixtureTime)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("configuration gate", err)
			}
		})
	}
}
func TestPrivateALBClientIPUsesOnlyTrustedLastHop(t *testing.T) {
	resolve := PrivateALBClientIP([]string{"10.0.0.0/24"})
	for _, scenario := range []struct {
		remote, forwarded, want string
		duplicate               bool
	}{
		{"10.0.0.20:1234", "192.0.2.10", "192.0.2.10", false},
		{"10.0.0.20:1234", "198.51.100.22, 192.0.2.10", "192.0.2.10", false},
		{"10.0.0.20:1234", "192.0.2.10, 198.51.100.22", "198.51.100.22", false},
		{"10.0.1.20:1234", "192.0.2.10", "", false},
		{"198.51.100.20:1234", "192.0.2.10", "", false},
		{"10.0.0.20:1234", "192.0.2.10:1234", "", false},
		{"10.0.0.20:1234", "192.0.2.10", "", true},
		{"10.0.0.20:1234", "", "", false},
	} {
		req := httptest.NewRequest("GET", "/csv/jobs/"+ID(), nil)
		req.RemoteAddr = scenario.remote
		if scenario.forwarded != "" {
			req.Header.Set("X-Forwarded-For", scenario.forwarded)
		}
		if scenario.duplicate {
			req.Header.Add("X-Forwarded-For", "192.0.2.10")
		}
		got, err := resolve(req)
		if scenario.want == "" {
			if err == nil {
				t.Fatal("untrusted client IP accepted")
			}
		} else if err != nil || got != netip.MustParseAddr(scenario.want) {
			t.Fatal("trusted client IP", got, err)
		}
	}
}
