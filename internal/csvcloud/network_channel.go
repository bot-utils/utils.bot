package csvcloud

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"pdfservice/internal/jsonwire"
	"slices"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// NetworkChannel bridges the broker to a controller and a separate read-only
// verifier process. Broker IAM permits request writes and proof reads only;
// verifier IAM has no DynamoDB writes. No verifier credential enters this type.
type NetworkChannel struct {
	Repo                  Repository
	RunID, JobID, TaskARN string
	PublicKey             ed25519.PublicKey
	Now                   func() time.Time
}

func (n NetworkChannel) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}
func (n NetworkChannel) requestKey() string {
	return "NETWORK_REQUEST/" + n.JobID + "/" + Hash([]byte(n.TaskARN))
}
func proofKey(b NetworkBinding) string { return "NETWORK_PROOF/" + b.JobID + "/" + b.Nonce }
func (n NetworkChannel) matches(b NetworkBinding) bool {
	return b.valid() && b.RunID == n.RunID && b.JobID == n.JobID && b.TaskARN == n.TaskARN && len(n.PublicKey) == ed25519.PublicKeySize
}
func (n NetworkChannel) VerifyAbsent(ctx context.Context, ids []string) error {
	now := n.now()
	b := NetworkBinding{RunID: n.RunID, JobID: n.JobID, TaskARN: n.TaskARN, Nonce: ID(), Interfaces: slices.Clone(ids), Issued: now.Unix(), Expires: now.Add(30 * time.Second).Unix()}
	if !n.matches(b) {
		return ErrInvalid
	}
	old, e := n.Repo.get(ctx, n.requestKey())
	if e != nil {
		return ErrCleanup
	}
	condition := "attribute_not_exists(pk)"
	var values map[string]d.AttributeValue
	var names map[string]string
	version := int64(1)
	if len(old) != 0 {
		v, ok := old["version"].(*d.AttributeValueMemberN)
		if !ok {
			return ErrCleanup
		}
		version = parseVersion(v.Value) + 1
		if version < 2 || version > 64 {
			return ErrCleanup
		}
		condition = "#v = :v"
		names = map[string]string{"#v": "version"}
		values = map[string]d.AttributeValue{":v": num(version - 1)}
	}
	raw, _ := json.Marshal(b)
	if n.Repo.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(n.Repo.Table), Item: map[string]d.AttributeValue{"pk": str(n.requestKey()), "version": num(version), "data": &d.AttributeValueMemberB{Value: raw}, "expires": num(b.Expires + 600)}, ConditionExpression: aws.String(condition), ExpressionAttributeValues: values, ExpressionAttributeNames: names}}}) != nil {
		return ErrCleanup
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		row, e := n.Repo.get(ctx, proofKey(b))
		if e != nil {
			return ErrCleanup
		}
		if len(row) != 0 {
			var proof NetworkProof
			v, ok := row["data"].(*d.AttributeValueMemberB)
			if !ok || len(v.Value) > 4096 || strictProof(v.Value, &proof) != nil {
				return ErrCleanup
			}
			return VerifyNetworkProof(proof, b, n.PublicKey, n.now())
		}
		if n.now().Unix() >= b.Expires {
			return ErrCleanup
		}
		select {
		case <-ctx.Done():
			return ErrCleanup
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Pending is a controller-only, strongly consistent read of the single pinned
// request. It cannot enumerate jobs or select worker/file locations from input.
func (n NetworkChannel) Pending(ctx context.Context) (NetworkBinding, error) {
	row, e := n.Repo.get(ctx, n.requestKey())
	if e != nil {
		return NetworkBinding{}, e
	}
	v, ok := row["data"].(*d.AttributeValueMemberB)
	if !ok || len(v.Value) > 4096 {
		return NetworkBinding{}, ErrUnknown
	}
	var b NetworkBinding
	if strictProof(v.Value, &b) != nil || !n.matches(b) || n.now().Unix() < b.Issued || n.now().Unix() >= b.Expires {
		return b, ErrCleanup
	}
	return b, nil
}

// Deliver conditionally stores an authenticated proof returned by the separate
// verifier. The broker's role must not be permitted to call this write.
func (n NetworkChannel) Deliver(ctx context.Context, p NetworkProof) error {
	if !n.matches(p.Binding) || VerifyNetworkProof(p, p.Binding, n.PublicKey, n.now()) != nil {
		return ErrCleanup
	}
	current, e := n.Pending(ctx)
	if e != nil || current.Nonce != p.Binding.Nonce {
		return ErrConflict
	}
	raw, _ := json.Marshal(p)
	return n.Repo.txn(ctx, []d.TransactWriteItem{{Put: &d.Put{TableName: aws.String(n.Repo.Table), Item: map[string]d.AttributeValue{"pk": str(proofKey(p.Binding)), "data": &d.AttributeValueMemberB{Value: raw}, "expires": num(p.Binding.Expires + 600)}, ConditionExpression: aws.String("attribute_not_exists(pk)")}}})
}

func parseVersion(v string) int64 {
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil {
		return -1
	}
	return n
}
func strictProof(raw []byte, v any) error { return jsonwire.Decode(raw, v, 4096) }
