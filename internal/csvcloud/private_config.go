package csvcloud

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"pdfservice/internal/csvwire"
	"pdfservice/internal/jsonwire"
)

// PrivateAPIConfig contains no raw test key or payment credential. Fixture
// identities are fixed by the operator, expire within two hours and are never
// advertised by discovery. The public tools' configuration is independent.
type PrivateAPIConfig struct {
	Account       string          `json:"account"`
	SyntheticOnly bool            `json:"synthetic_only"`
	AllowedIP     string          `json:"allowed_ip"`
	KeySHA256     string          `json:"key_sha256"`
	ALBPeers      []string        `json:"alb_peers"`
	Runs          []PrivateAPIRun `json:"runs"`
}
type PrivateAPIRun struct {
	ID      string            `json:"id"`
	Until   int64             `json:"until"`
	Request csvwire.Request   `json:"request"`
	Parts   map[string][]Part `json:"parts,omitempty"`
}

func ParsePrivateAPIConfig(raw []byte, now time.Time) (PrivateAPIConfig, error) {
	var c PrivateAPIConfig
	if jsonwire.Decode(raw, &c, 32<<10) != nil || c.Account != "999999999999" || !c.SyntheticOnly || !opaque(c.KeySHA256) || len(c.Runs) < 1 || len(c.Runs) > 5 || len(c.ALBPeers) < 1 || len(c.ALBPeers) > 4 {
		return c, ErrInvalid
	}
	ip, err := netip.ParseAddr(c.AllowedIP)
	if err != nil || !ip.Is4() || ip.String() != c.AllowedIP || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return c, ErrInvalid
	}
	for _, raw := range c.ALBPeers {
		peer, err := netip.ParsePrefix(raw)
		if err != nil || !peer.Addr().Is4() || !peer.Addr().IsPrivate() || peer.Bits() < 24 || peer.String() != raw || peer != peer.Masked() {
			return c, ErrInvalid
		}
	}
	ids, bindings := map[string]bool{}, map[string]bool{}
	for _, run := range c.Runs {
		if !opaque(run.ID) || run.Until <= 0 || run.Until > now.Add(2*time.Hour).Unix() || run.Request.Validate() != nil || !privatePartPlanValid(run) || ids[run.ID] || bindings[run.Request.Binding()] {
			return c, ErrInvalid
		}
		ids[run.ID] = true
		bindings[run.Request.Binding()] = true
	}
	return c, nil
}

// PrivateALBClientIP is valid only behind the named ALB's existing task-only
// security group, with XFF append mode and client-port inclusion disabled.
// The final appended address is the network client, never the caller's prefix.
func PrivateALBClientIP(peers []string) func(*http.Request) (netip.Addr, error) {
	prefixes := make([]netip.Prefix, 0, len(peers))
	for _, raw := range peers {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil
		}
		prefixes = append(prefixes, p)
	}
	return func(r *http.Request) (netip.Addr, error) {
		remote, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			return netip.Addr{}, ErrInvalid
		}
		trusted := false
		for _, p := range prefixes {
			if p.Contains(remote.Addr().Unmap()) {
				trusted = true
				break
			}
		}
		if !trusted || len(r.Header.Values("X-Forwarded-For")) != 1 {
			return netip.Addr{}, ErrInvalid
		}
		addresses := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		ip, err := netip.ParseAddr(strings.TrimSpace(addresses[len(addresses)-1]))
		if err != nil || !ip.Is4() {
			return netip.Addr{}, ErrInvalid
		}
		return ip, nil
	}
}
func NewPrivateAWSHTTP(raw []byte, cfg aws.Config) (http.Handler, error) {
	c, err := ParsePrivateAPIConfig(raw, time.Now())
	if err != nil {
		return nil, err
	}
	// CSV's metadata and bounded download streams may outlive the normal short
	// SDK deadline. Copy this client; do not change public PDF/payment clients.
	client, ok := cfg.HTTPClient.(*http.Client)
	if !ok {
		return nil, ErrInvalid
	}
	copied := *client
	copied.Timeout = 90 * time.Second
	cfg.HTTPClient = &copied
	a, err := clients(cfg)
	if err != nil {
		return nil, err
	}
	backends := PrivateBackendSet{}
	for _, run := range c.Runs {
		repo := Repository{Client: a.Dynamo, Table: "utils-bot-csv-private-" + run.ID[:16], Gate: Gate{Enabled: true}}
		objects := Storage{Client: a.S3, Presigner: a.Parts, Bucket: "utils-csv-" + c.Account + "-" + run.ID[:24], Account: c.Account, Gate: Gate{Enabled: true}}
		queue := Queue{Client: a.SQS, URL: "https://sqs.us-east-2.amazonaws.com/" + c.Account + "/" + repo.Table, Repo: repo, Gate: Gate{Enabled: true}}
		backends[run.ID] = &PrivateRunBackend{RunID: run.ID, Until: run.Until, SyntheticOnly: true, Request: run.Request, Parts: run.Parts, Repo: repo, Objects: objects, Queue: queue}
	}
	return PrivateHTTP{Enabled: true, SyntheticOnly: true, AllowedIP: netip.MustParseAddr(c.AllowedIP), KeySHA256: c.KeySHA256, ClientIP: PrivateALBClientIP(c.ALBPeers), Backend: backends}, nil
}

func privatePartPlanValid(run PrivateAPIRun) bool {
	if run.Request.Version == 1 && len(run.Parts) == 0 {
		return true
	}
	if len(run.Parts) != len(run.Request.Files) {
		return false
	}
	for _, f := range run.Request.Files {
		parts := run.Parts[f.Slot]
		u := Upload{Object: Object{JobID: run.ID, ID: run.ID, Slot: f.Slot, Bytes: f.Bytes, SHA256: f.SHA256}, Parts: parts}
		if !u.valid() || len(parts) > 16 {
			return false
		}
		for _, p := range parts {
			if p.Bytes > 64<<20 {
				return false
			}
		}
	}
	return true
}
