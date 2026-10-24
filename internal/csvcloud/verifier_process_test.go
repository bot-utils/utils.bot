package csvcloud

import (
	"context"
	"crypto/ed25519"
	"github.com/aws/aws-sdk-go-v2/aws"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifierExecutesPinnedInodeWithPipeKeyAndNoInheritedSecrets(t *testing.T) {
	directory, e := os.MkdirTemp("", "csv-verifier-process-")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if exec.Command("trash", directory).Run() != nil {
			t.Error("owned verifier fixture cleanup")
		}
	}()
	source := `package main
import("crypto/ed25519";"encoding/base64";"encoding/json";"io";"os")
type binding struct{RunID,JobID,TaskARN,Nonce string;Interfaces []string;Issued,Expires int64}
func main(){if os.Getenv("SHOULD_NOT_INHERIT")!=""||os.Getenv("CSV_VERIFIER_KEY")!=""||os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")!=""||os.Getenv("AWS_ACCESS_KEY_ID")!="test-verifier"||os.Getenv("CSV_VERIFIER_KEY_FD")!="4"{os.Exit(78)};key,_:=io.ReadAll(io.LimitReader(os.NewFile(4,"key"),65));if len(key)!=64{os.Exit(78)};var b binding;if json.NewDecoder(os.Stdin).Decode(&b)!=nil{os.Exit(78)};raw,_:=json.Marshal(b);signature:=ed25519.Sign(ed25519.PrivateKey(key),append([]byte("csv-network-absent-v1|"),raw...));json.NewEncoder(os.Stdout).Encode(struct{Binding binding;Signature string}{b,base64.StdEncoding.EncodeToString(signature)})}`
	sourcePath := filepath.Join(directory, "main.go")
	binary := filepath.Join(directory, "verifier")
	if os.WriteFile(sourcePath, []byte(source), 0600) != nil {
		t.Fatal("fixture source")
	}
	if exec.Command("go", "build", "-trimpath", "-o", binary, sourcePath).Run() != nil {
		t.Fatal("fixture build")
	}
	raw, e := os.ReadFile(binary)
	if e != nil || os.Chmod(binary, 0555) != nil {
		t.Fatal("readonly fixture")
	}
	b, _, key := networkFixture()
	now := time.Now()
	b.Issued = now.Unix()
	b.Expires = now.Add(30 * time.Second).Unix()
	t.Setenv("SHOULD_NOT_INHERIT", "private")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/must-not-inherit")
	verifier := VerifierProcess{Executable: binary, BinarySHA: Hash(raw), RunID: b.RunID, JobID: b.JobID, Key: key, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test-verifier", SecretAccessKey: "synthetic", SessionToken: "synthetic", CanExpire: true, Expires: now.Add(time.Hour)}, nil
	})}
	proof, e := verifier.Proof(ctx, StoppedObserver{TaskARN: b.TaskARN}, b)
	if e != nil || VerifyNetworkProof(proof, b, key.Public().(ed25519.PublicKey), time.Now()) != nil {
		t.Fatal("pinned process/pipe isolation", e)
	}
	if os.Chmod(binary, 0755) != nil {
		t.Fatal("fixture mode")
	}
	if _, e = verifier.Proof(ctx, StoppedObserver{TaskARN: b.TaskARN}, b); e == nil {
		t.Fatal("writable executable accepted")
	}
}
