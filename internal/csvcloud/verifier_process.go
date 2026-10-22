package csvcloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type VerifierScope struct{ Kind, Bucket, Account, RunID, JobID, Cluster, TaskARN, Definition, Group, StartedBy string }

// VerifierProcess passes only short-lived read-only session credentials to a
// hash-pinned child, with no inherited environment, profiles, broker credentials,
// container credential URI or IMDS fallback. Stdout is bounded signed metadata;
// raw provider diagnostics are discarded.
type VerifierProcess struct {
	Executable, BinarySHA, RunID, JobID string
	Credentials                         aws.CredentialsProvider
	Key                                 ed25519.PrivateKey
	Now                                 func() time.Time
}

func (v VerifierProcess) Proof(ctx context.Context, scope StoppedObserver, b NetworkBinding) (NetworkProof, error) {
	if !filepath.IsAbs(v.Executable) || !opaque(v.BinarySHA) || v.Credentials == nil || len(v.Key) != ed25519.PrivateKeySize || b.RunID != v.RunID || b.JobID != v.JobID || scope.TaskARN != b.TaskARN {
		return NetworkProof{}, ErrInvalid
	}
	binary, e := v.openBinary()
	if e != nil {
		return NetworkProof{}, e
	}
	defer binary.Close()

	credential, e := v.Credentials.Retrieve(ctx)
	if e != nil || credential.SessionToken == "" || !credential.CanExpire || credential.Expires.Before(time.Unix(b.Expires, 0)) {
		return NetworkProof{}, ErrCleanup
	}
	expected := VerifierScope{Kind: "network", RunID: v.RunID, JobID: v.JobID, Cluster: scope.Cluster, TaskARN: scope.TaskARN, Definition: scope.Definition, Group: scope.Group, StartedBy: scope.StartedBy}
	raw, _ := json.Marshal(b)
	settings, _ := json.Marshal(expected)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	path, e := v.execPath(binary)
	if e != nil {
		return NetworkProof{}, e
	}
	command := exec.CommandContext(ctx, path)
	keyPipe, e := v.attach(command, binary)
	if e != nil {
		return NetworkProof{}, e
	}
	defer keyPipe.Close()
	command.Env = []string{"AWS_REGION=" + Region, "AWS_ACCESS_KEY_ID=" + credential.AccessKeyID, "AWS_SECRET_ACCESS_KEY=" + credential.SecretAccessKey, "AWS_SESSION_TOKEN=" + credential.SessionToken, "CSV_VERIFIER_KEY_FD=4", "CSV_VERIFIER_SCOPE=" + string(settings)}
	command.Stdin = bytes.NewReader(raw)
	var out boundedProof
	command.Stdout = &out
	command.Stderr = io.Discard
	if command.Run() != nil {
		return NetworkProof{}, ErrCleanup
	}
	var proof NetworkProof
	if strictProof(out.Bytes(), &proof) != nil {
		return proof, ErrCleanup
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if VerifyNetworkProof(proof, b, v.Key.Public().(ed25519.PublicKey), now) != nil {
		return proof, ErrCleanup
	}
	return proof, nil
}

type boundedProof struct{ value bytes.Buffer }

func (b *boundedProof) Write(p []byte) (int, error) {
	if len(p) > 4096-b.value.Len() {
		return 0, ErrCleanup
	}
	return b.value.Write(p)
}
func (b *boundedProof) Bytes() []byte { return b.value.Bytes() }

// VerifyBucket runs the separate read-only verifier, including its bounded
// convergence window, rather than reusing the controller's sealer credentials.
func (v VerifierProcess) VerifyBucket(ctx context.Context, bucket, account string) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	b := BucketBinding{RunID: v.RunID, JobID: v.JobID, Nonce: ID(), Bucket: bucket, Account: account, Issued: now.Unix(), Expires: now.Add(45 * time.Second).Unix()}
	if !b.valid() || len(v.Key) != ed25519.PrivateKeySize || !filepath.IsAbs(v.Executable) || !opaque(v.BinarySHA) || v.Credentials == nil {
		return ErrInvalid
	}
	binary, e := v.openBinary()
	if e != nil {
		return e
	}
	defer binary.Close()

	credential, e := v.Credentials.Retrieve(ctx)
	if e != nil || credential.SessionToken == "" || !credential.CanExpire || credential.Expires.Before(time.Unix(b.Expires, 0)) {
		return ErrCleanup
	}
	expected := VerifierScope{Kind: "bucket", RunID: v.RunID, JobID: v.JobID, Bucket: bucket, Account: account}
	raw, _ := json.Marshal(b)
	settings, _ := json.Marshal(expected)
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	path, e := v.execPath(binary)
	if e != nil {
		return e
	}
	command := exec.CommandContext(ctx, path)
	keyPipe, e := v.attach(command, binary)
	if e != nil {
		return e
	}
	defer keyPipe.Close()
	command.Env = []string{"AWS_REGION=" + Region, "AWS_ACCESS_KEY_ID=" + credential.AccessKeyID, "AWS_SECRET_ACCESS_KEY=" + credential.SecretAccessKey, "AWS_SESSION_TOKEN=" + credential.SessionToken, "CSV_VERIFIER_KEY_FD=4", "CSV_VERIFIER_SCOPE=" + string(settings)}
	command.Stdin = bytes.NewReader(raw)
	var out boundedProof
	command.Stdout = &out
	command.Stderr = io.Discard
	if command.Run() != nil {
		return ErrCleanup
	}
	var p BucketProof
	if strictProof(out.Bytes(), &p) != nil {
		return ErrCleanup
	}
	now = time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	return VerifyBucketProof(p, b, v.Key.Public().(ed25519.PublicKey), now)
}

// Linux executes the verified inode through fd3. Darwin disallows executable
// /dev/fd paths; its explicit profile requires an owner-only directory and an
// owned read-only file, and rechecks inode identity immediately before launch.
// Host-account compromise is outside this broker/container isolation boundary.
func (v VerifierProcess) execPath(binary *os.File) (string, error) {
	if runtime.GOOS == "linux" {
		return "/proc/self/fd/3", nil
	}
	if runtime.GOOS != "darwin" {
		return "", ErrInvalid
	}
	directory, e := os.Lstat(filepath.Dir(v.Executable))
	if e != nil || !directory.IsDir() || directory.Mode().Perm()&0077 != 0 {
		return "", ErrInvalid
	}
	st, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return "", ErrInvalid
	}
	opened, e := binary.Stat()
	if e != nil {
		return "", ErrInvalid
	}
	current, e := os.Lstat(v.Executable)
	if e != nil || !os.SameFile(opened, current) || current.Mode().Perm()&0222 != 0 {
		return "", ErrInvalid
	}
	return v.Executable, nil
}

func (v VerifierProcess) openBinary() (*os.File, error) {
	info, e := os.Lstat(v.Executable)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 {
		return nil, ErrInvalid
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return nil, ErrInvalid
	}
	f, e := os.Open(v.Executable)
	if e != nil {
		return nil, ErrInvalid
	}
	current, e := f.Stat()
	if e != nil || !os.SameFile(info, current) || current.Size() > 64<<20 {
		f.Close()
		return nil, ErrInvalid
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (64<<20)+1))
	if e != nil || n > 64<<20 || hex.EncodeToString(h.Sum(nil)) != v.BinarySHA {
		f.Close()
		return nil, ErrInvalid
	}
	if _, e = f.Seek(0, 0); e != nil {
		f.Close()
		return nil, ErrInvalid
	}
	return f, nil
}
func (v VerifierProcess) attach(c *exec.Cmd, binary *os.File) (*os.File, error) {
	r, w, e := os.Pipe()
	if e != nil {
		return nil, ErrInvalid
	}
	if _, e = w.Write(v.Key); e != nil {
		r.Close()
		w.Close()
		return nil, ErrInvalid
	}
	w.Close()
	c.ExtraFiles = []*os.File{binary, r}
	return r, nil
}
