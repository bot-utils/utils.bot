package csvcloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// EC2Reader runs only in the independent verifier process, under a separate
// read-only identity. No EC2 credential/provider is passed into the broker.
type EC2Reader struct{ config aws.Config }

func NewEC2Reader(c aws.Config) (EC2Reader, error) {
	if c.Region != Region || c.BaseEndpoint != nil || c.Credentials == nil || c.HTTPClient == nil {
		return EC2Reader{}, ErrInvalid
	}
	return EC2Reader{c}, nil
}

var eniPattern = regexp.MustCompile(`^eni-[0-9a-f]{8,17}$`)

func interfaceIDs(ids []string) bool { return len(ids) == 1 && eniPattern.MatchString(ids[0]) }
func (r EC2Reader) VerifyAbsent(ctx context.Context, ids []string) error {
	if !interfaceIDs(ids) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	values := url.Values{"Action": {"DescribeNetworkInterfaces"}, "Version": {"2016-11-15"}, "NetworkInterfaceId.1": {ids[0]}}
	payload := values.Encode()
	request, e := http.NewRequestWithContext(ctx, "POST", "https://ec2.us-east-2.amazonaws.com/", strings.NewReader(payload))
	if e != nil {
		return ErrCleanup
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	credential, e := r.config.Credentials.Retrieve(ctx)
	if e != nil {
		return ErrCleanup
	}
	h := sha256.Sum256([]byte(payload))
	if v4.NewSigner().SignHTTP(ctx, credential, request, hex.EncodeToString(h[:]), "ec2", Region, time.Now()) != nil {
		return ErrCleanup
	}
	response, e := r.config.HTTPClient.Do(request)
	if e != nil {
		return ErrCleanup
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if e != nil || len(raw) > 64<<10 {
		return ErrCleanup
	}
	// Query one exact ID per request. A multi-ID NotFound response could hide
	// another interface that still exists. Empty/malformed 200 is not absence.
	var failure struct {
		XMLName xml.Name
		Errors  []struct {
			Code string `xml:"Code"`
		} `xml:"Errors>Error"`
	}
	if response.StatusCode != 400 || xml.Unmarshal(raw, &failure) != nil || failure.XMLName.Local != "Response" || len(failure.Errors) != 1 || failure.Errors[0].Code != "InvalidNetworkInterfaceID.NotFound" {
		return ErrCleanup
	}
	return nil
}

type NetworkBinding struct {
	RunID, JobID, TaskARN, Nonce string
	Interfaces                   []string
	Issued, Expires              int64
}

func (b NetworkBinding) valid() bool {
	return opaque(b.RunID) && opaque(b.JobID) && opaque(b.Nonce) && interfaceIDs(b.Interfaces) && strings.HasPrefix(b.TaskARN, "arn:aws:ecs:us-east-2:") && strings.Contains(b.TaskARN, ":task/") && b.Issued > 0 && b.Expires > b.Issued && b.Expires-b.Issued <= 30
}

type NetworkProof struct {
	Binding   NetworkBinding
	Signature string
}

func (NetworkProof) String() string   { return "CSV network proof [redacted]" }
func (NetworkProof) GoString() string { return "CSV network proof [redacted]" }
func proofPayload(b NetworkBinding) []byte {
	v, _ := json.Marshal(b)
	return append([]byte("csv-network-absent-v1|"), v...)
}

// SignNetworkProof is called by the isolated verifier after independently
// obtaining stopped ECS state and exact attachment IDs through its pinned task
// observer. The broker cannot provide a bare 'stopped' boolean as evidence.
func SignNetworkProof(ctx context.Context, b NetworkBinding, key ed25519.PrivateKey, observe func(context.Context) (string, []string, error), reader NetworkGone, now time.Time) (NetworkProof, error) {
	if !b.valid() || len(key) != ed25519.PrivateKeySize || observe == nil || reader == nil || now.Unix() < b.Issued || now.Unix() >= b.Expires {
		return NetworkProof{}, ErrInvalid
	}
	task, ids, e := observe(ctx)
	if e != nil || task != b.TaskARN || !slices.Equal(ids, b.Interfaces) || reader.VerifyAbsent(ctx, ids) != nil {
		return NetworkProof{}, ErrCleanup
	}
	return NetworkProof{b, base64.StdEncoding.EncodeToString(ed25519.Sign(key, proofPayload(b)))}, nil
}
func VerifyNetworkProof(p NetworkProof, b NetworkBinding, key ed25519.PublicKey, now time.Time) error {
	if !b.valid() || len(key) != ed25519.PublicKeySize || now.Unix() < b.Issued || now.Unix() >= b.Expires {
		return ErrCleanup
	}
	a, _ := json.Marshal(p.Binding)
	expected, _ := json.Marshal(b)
	signature, e := base64.StdEncoding.DecodeString(p.Signature)
	if e != nil || !bytes.Equal(a, expected) || !ed25519.Verify(key, proofPayload(b), signature) {
		return ErrCleanup
	}
	return nil
}

// Bucket proofs attest the convergence protocol, not a general claim that S3
// propagation is instantaneous. The actual delayed-PUT AWS gate remains required.
type BucketBinding struct {
	RunID, JobID, Nonce, Bucket, Account string
	Issued, Expires                      int64
}
type BucketProof struct {
	Binding   BucketBinding
	Signature string
}

func (b BucketBinding) valid() bool {
	return opaque(b.RunID) && opaque(b.JobID) && opaque(b.Nonce) && b.Bucket == "utils-csv-"+b.Account+"-"+b.RunID[:24] && regexp.MustCompile(`^[0-9]{12}$`).MatchString(b.Account) && b.Issued > 0 && b.Expires > b.Issued && b.Expires-b.Issued <= 45
}
func bucketPayload(b BucketBinding) []byte {
	raw, _ := json.Marshal(b)
	return append([]byte("csv-bucket-absent-v1|"), raw...)
}
func VerifyBucketProof(p BucketProof, b BucketBinding, key ed25519.PublicKey, now time.Time) error {
	a, _ := json.Marshal(p.Binding)
	expected, _ := json.Marshal(b)
	signature, e := base64.StdEncoding.DecodeString(p.Signature)
	if !b.valid() || now.Unix() < b.Issued || now.Unix() >= b.Expires || len(key) != ed25519.PublicKeySize || e != nil || !bytes.Equal(a, expected) || !ed25519.Verify(key, bucketPayload(b), signature) {
		return ErrCleanup
	}
	return nil
}
func SignBucketProof(ctx context.Context, b BucketBinding, key ed25519.PrivateKey, reader BucketAbsence) (BucketProof, error) {
	if !b.valid() || len(key) != ed25519.PrivateKeySize || reader.Bucket != b.Bucket || reader.Account != b.Account || time.Now().Unix() < b.Issued || time.Now().Unix() >= b.Expires || reader.Verify(ctx) != nil {
		return BucketProof{}, ErrCleanup
	}
	p := BucketProof{Binding: b, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, bucketPayload(b)))}
	if VerifyBucketProof(p, b, key.Public().(ed25519.PublicKey), time.Now()) != nil {
		return p, ErrCleanup
	}
	return p, nil
}
