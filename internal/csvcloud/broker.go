package csvcloud

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"pdfservice/internal/csvwire"
	"pdfservice/internal/jsonwire"
)

// BrokerBootstrap enters only the private broker's encrypted per-run Secrets
// reference. It never appears in ECS commands, task metadata or logs. Its task role receives
// exact-original-worker lifecycle permission after that ARN is known. No extra
// lifecycle credentials or assume-role permission enter the broker.
type BrokerBootstrap struct {
	RunID, JobID, Account, Table, Bucket, Cluster, Definition, Subnet, Prefix, NetworkPublicKey string
	Until                                                                                       int64
	Review                                                                                      WireReview
	Request                                                                                     csvwire.Request
	Identity                                                                                    csvwire.Bootstrap
}

func (BrokerBootstrap) String() string   { return "CSV broker bootstrap [redacted]" }
func (BrokerBootstrap) GoString() string { return "CSV broker bootstrap [redacted]" }
func DecodeBroker(raw []byte, now time.Time) (BrokerBootstrap, error) {
	var b BrokerBootstrap
	if jsonwire.Decode(raw, &b, 8192) != nil || !opaque(b.RunID) || !opaque(b.JobID) || !b.Review.valid() || b.Account != b.Review.Account || b.RunID != b.Review.RunID || b.Table != "utils-bot-csv-private-"+b.RunID[:16] || b.Bucket != "utils-csv-"+b.Account+"-"+b.RunID[:24] || b.Cluster != "arn:aws:ecs:us-east-2:"+b.Account+":cluster/utils-bot-csv-trial" || b.Subnet != "subnet-00000000000000001" || b.Prefix != "10.88.0.0/24" || b.Until <= now.Unix() || b.Until > now.Add(10*time.Minute).Unix() || b.Request.Validate() != nil || b.Request.Operation != "join" {
		return b, ErrInvalid
	}
	var total int64
	for _, f := range b.Request.Files {
		total += f.Bytes
	}
	if total != 1<<20 {
		return b, ErrInvalid
	}

	key, e := base64.StdEncoding.DecodeString(b.NetworkPublicKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return b, ErrInvalid
	}
	return b, nil
}

// ProcessSyntheticBroker assembles the real S3/Dynamo/ECS/private-TLS adapters.
// No payment/provider/RPC client, dispatch or HTTP route is invoked. Recovery
// belongs to the separate controller: it must not execute inside the task it stops.
func ProcessSyntheticBroker(ctx context.Context, b BrokerBootstrap, data aws.Config) error {
	now := time.Now()
	raw, e := json.Marshal(b)
	if e != nil {
		return ErrInvalid
	}
	if _, e = DecodeBroker(raw, now); e != nil {
		return e
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(b.Until, 0))
	defer cancel()
	clients, e := clients(data)
	if e != nil {
		return e
	}
	repo := Repository{Client: clients.Dynamo, Table: b.Table, Gate: Gate{Enabled: true}}
	j, e := repo.Get(ctx, b.JobID)
	if e != nil || j == nil || j.Dispatch == nil || j.IntentBinding != b.Request.Binding() {
		return ErrInvalid
	}
	tlsConfig, e := csvwire.ClientTLS(b.Identity, now)
	if e != nil {
		return ErrInvalid
	}

	pub, _ := base64.StdEncoding.DecodeString(b.NetworkPublicKey)
	channel := NetworkChannel{Repo: repo, RunID: b.RunID, JobID: b.JobID, TaskARN: j.Dispatch.TaskARN, PublicKey: ed25519.PublicKey(pub)}
	worker := PrivateWorker{Review: &b.Review, Client: clients.ECS, Verifier: channel, Cluster: b.Cluster, Definition: b.Definition, Subnet: b.Subnet, Prefix: netip.MustParsePrefix(b.Prefix), TLS: tlsConfig, Gate: Gate{Enabled: true}}
	processor := Processor{Repo: repo, Objects: privateCandidateStorage{Storage{Client: clients.S3, Bucket: b.Bucket, Account: b.Account, Gate: Gate{Enabled: true}}}, Worker: worker.Session(), Gate: Gate{Enabled: true}, StageResults: true}
	return processor.Process(ctx, b.JobID, b.Request)
}
