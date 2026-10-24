package csvcloud

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	tabular "pdfservice/internal/csvtabular"
	"pdfservice/internal/csvwire"
	"pdfservice/internal/jsonwire"
)

type privateHTTPFixtureData struct {
	Request       csvwire.Request
	Inputs        map[string][]byte
	Expected      []byte
	Rows          int64
	Parts         map[string][]Part
	ExpectedBytes int64
	ExpectedSHA   string
	Open          func(string, int64, int64) (io.ReadCloser, error)
}

func privateSmallFixture(op string) (privateHTTPFixtureData, error) {
	if op == "" || op == "join" {
		q, in, want := privateJoinFixture()
		return privateHTTPFixtureData{Request: q, Inputs: in, Expected: want, Rows: 1024}, nil
	}
	encode := func(rows [][]string) []byte {
		var b bytes.Buffer
		w := csv.NewWriter(&b)
		_ = w.WriteAll(rows)
		w.Flush()
		return b.Bytes()
	}
	var input, want [][]string
	var raw string
	switch op {
	case "dedupe":
		input = [][]string{{"id", "value"}, {"1", "first"}, {"1", "duplicate"}, {"2", "二,comma"}, {"3", "line\nbreak"}, {"2", "discard"}}
		want = [][]string{input[0], input[1], input[3], input[4]}
		raw = `{"key_columns":["id"],"keep":"first"}`
	case "aggregate":
		input = [][]string{{"group", "value"}, {"team,red", "a"}, {"team,red", "b"}, {"team,red", "c"}}
		want = [][]string{{"group", "n"}, {"team,red", "3"}}
		raw = `{"group_columns":["group"],"metrics":[{"name":"n","op":"count_rows"}]}`
	case "transform":
		input = [][]string{{"id", "value", "other"}, {"1", "Abcé", "keep"}, {"2", "ß", "unchanged"}, {"3", "a\nb", "x,y"}, {"4", "", ""}}
		want = [][]string{{"id", "value", "other"}, {"1", "ABCÉ", "keep"}, {"2", "ß", "unchanged"}, {"3", "A\nB", "x,y"}, {"4", "", ""}}
		raw = `{"column":"value","op":"upper"}`
	default:
		return privateHTTPFixtureData{}, ErrInvalid
	}
	options, err := tabular.CanonicalOptions(op, json.RawMessage(raw))
	if err != nil {
		return privateHTTPFixtureData{}, err
	}
	data := encode(input)
	q := csvwire.Request{Version: 1, Operation: op, Options: options, Files: []csvwire.File{{Slot: "file", Bytes: int64(len(data)), SHA256: Hash(data)}}}
	return privateHTTPFixtureData{Request: q, Inputs: map[string][]byte{"file": data}, Expected: encode(want), Rows: int64(len(want) - 1)}, nil
}
func TestPrivateSmallHTTPFixtureOracles(t *testing.T) {
	for _, op := range []string{"dedupe", "join", "aggregate", "transform"} {
		t.Run(op, func(t *testing.T) {
			f, e := privateSmallFixture(op)
			if e != nil {
				t.Fatal(e)
			}
			inputs := map[string]io.Reader{}
			for slot, p := range f.Inputs {
				inputs[slot] = bytes.NewReader(p)
			}
			var request, result, encoded bytes.Buffer
			if csvwire.WriteRequest(&request, f.Request, inputs) != nil || csvwire.Process(&request, &result) != nil {
				t.Fatal("fixture execution")
			}
			m, e := csvwire.ReadResult(&result, &encoded)
			if e != nil || m.LogicalSHA256 != f.logicalSHA() || int64(m.Rows) != f.Rows || m.LogicalBytes != int64(len(f.Expected)) {
				t.Fatal("independent fixture oracle", e)
			}
		})
	}
}

var errPrivateAPIDraining = errors.New("private_csv_draining")

type privateAPIClient struct {
	HTTP aws.HTTPClient
	Key  string
}

func newPrivateAPIClient(cfg aws.Config) (privateAPIClient, error) {
	key := os.Getenv("CSV_PRIVATE_API_KEY")
	if !opaque(key) {
		return privateAPIClient{}, ErrInvalid
	}
	client, ok := cfg.HTTPClient.(*http.Client)
	if !ok {
		return privateAPIClient{}, ErrInvalid
	}
	copy := *client
	copy.Timeout = 90 * time.Second
	return privateAPIClient{&copy, key}, nil
}
func (a privateAPIClient) request(ctx context.Context, method, path string, body any, want int, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return ErrInvalid
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.utils.bot"+path, reader)
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("X-CSV-Test-Key", a.Key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return ErrUnknown
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxMetadata+1))
	if err != nil || len(data) > MaxMetadata {
		return fmt.Errorf("response_body: %w", ErrIntegrity)
	}
	if resp.StatusCode != want {
		if resp.StatusCode == 503 && resp.Header.Get("Retry-After") == "1" && bytes.Equal(bytes.TrimSpace(data), []byte(`{"error":"draining"}`)) {
			return errPrivateAPIDraining
		}
		return fmt.Errorf("response_status_%d: %w", resp.StatusCode, ErrIntegrity)
	}
	if resp.Header.Get("X-CSV-Payment-Mode") != "synthetic-no-funds" {
		return fmt.Errorf("response_payment_mode: %w", ErrIntegrity)
	}
	if out != nil && jsonwire.Decode(data, out, MaxMetadata) != nil {
		return fmt.Errorf("response_decode: %w", ErrIntegrity)
	}
	return nil
}

// Retry only an explicit pre-backend drain rejection of a replay whose first
// admission already returned 201. First admission, completion, uploads, worker
// starts and payments are never retried here. Generic 503s remain failures.
func (a privateAPIClient) confirmedAdmissionReplay(ctx context.Context, path string, body any, known PrivateAdmission, replay *PrivateAdmission) error {
	if !opaque(known.JobID) || known.Expires <= time.Now().Unix() || len(known.Parts) == 0 {
		return ErrInvalid
	}
	for attempt := 0; attempt < 3; attempt++ {
		err := a.request(ctx, "POST", path, body, 201, replay)
		if !errors.Is(err, errPrivateAPIDraining) || attempt == 2 {
			return err
		}
		if known.Expires <= time.Now().Unix()+1 {
			return ErrConflict
		}
		if client, ok := a.HTTP.(interface{ CloseIdleConnections() }); ok {
			client.CloseIdleConnections()
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ErrUnknown
}

func (a privateAPIClient) admit(ctx context.Context, run string, f privateHTTPFixtureData, storage Storage) (PrivateAdmission, error) {
	body := struct {
		Options  json.RawMessage `json:"options"`
		Files    []csvwire.File  `json:"files"`
		Delivery string          `json:"delivery"`
	}{f.Request.Options, f.Request.Files, "gzip"}
	var admission PrivateAdmission
	if e := a.request(ctx, "POST", "/csv/"+f.Request.Operation, body, 201, &admission); e != nil {
		return admission, fmt.Errorf("admission_request: %w", e)
	}
	if admission.JobID != run || admission.Expires <= time.Now().Unix() || len(admission.Parts) != f.partCount() || admission.PaymentMode != "synthetic-no-funds" {
		return admission, fmt.Errorf("admission_binding: %w", ErrIntegrity)
	}
	var replay PrivateAdmission
	if e := a.confirmedAdmissionReplay(ctx, "/csv/"+f.Request.Operation, body, admission, &replay); e != nil || replay.JobID != admission.JobID || len(replay.Parts) != len(admission.Parts) {
		if e != nil {
			return admission, fmt.Errorf("admission_replay: %w", e)
		}
		return admission, fmt.Errorf("admission_replay_binding: %w", ErrIntegrity)
	}
	// No test key, payer data or payment header is ever sent to an upload URL.
	for _, part := range admission.Parts {
		expected, offset, ok := f.part(part.Slot, part.Number)
		u, e := url.Parse(part.URL)
		if !ok || e != nil || u.Scheme != "https" || u.Host != storage.Bucket+".s3.us-east-2.amazonaws.com" || u.User != nil || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/inputs/"+run+"/") || !opaque(strings.TrimPrefix(u.Path, "/inputs/"+run+"/")) || u.Query().Get("partNumber") != strconv.Itoa(int(part.Number)) || u.Query().Get("uploadId") == "" {
			return admission, fmt.Errorf("upload_grant_url: %w", ErrIntegrity)
		}
		h := http.Header(part.Headers)
		if h.Get("Content-Length") != strconv.FormatInt(expected.Bytes, 10) || h.Get("X-Amz-Checksum-Sha256") != checksum(expected.SHA256) || h.Get("X-CSV-Test-Key") != "" || h.Get("Payment-Signature") != "" {
			return admission, fmt.Errorf("upload_grant_headers: %w", ErrIntegrity)
		}
		source, e := f.open(part.Slot, offset, expected.Bytes)
		if e != nil {
			return admission, e
		}
		req, e := http.NewRequestWithContext(ctx, "PUT", part.URL, source)
		if e != nil {
			return admission, ErrInvalid
		}
		req.Header = h.Clone()
		req.ContentLength = expected.Bytes
		resp, e := a.HTTP.Do(req)
		source.Close()
		if e != nil {
			return admission, ErrUnknown
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return admission, fmt.Errorf("upload_status_%d: %w", resp.StatusCode, ErrIntegrity)
		}
	}
	if e := a.request(ctx, "POST", "/csv/jobs/"+run+"/uploads/complete", struct{}{}, 202, nil); e != nil {
		return admission, fmt.Errorf("upload_complete_signal: %w", e)
	}
	return admission, nil
}
func (a privateAPIClient) verifyResult(ctx context.Context, j Job, f privateHTTPFixtureData) error {
	path := "/csv/jobs/" + j.ID
	if err := a.request(ctx, "GET", path+"/download", nil, 402, nil); err != nil {
		return err
	}
	if err := a.request(ctx, "POST", path+"/payment", map[string]string{"mode": "cdp-base"}, 400, nil); err != nil {
		return err
	}
	if err := a.request(ctx, "POST", path+"/payment", map[string]string{"mode": "synthetic-no-funds"}, 202, nil); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.utils.bot"+path+"/download", nil)
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("X-CSV-Test-Key", a.Key)
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return ErrUnknown
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/gzip" || resp.ContentLength != j.Result.Object.Bytes {
		return ErrIntegrity
	}
	encoded := &countingHash{H: sha256.New()}
	z, err := gzip.NewReader(io.TeeReader(io.LimitReader(resp.Body, j.Result.Object.Bytes+1), encoded))
	if err != nil {
		return ErrIntegrity
	}
	logical := sha256.New()
	n, err := io.Copy(logical, io.LimitReader(z, f.logicalBytes()+1))
	closed := z.Close()
	if err != nil || closed != nil || n != f.logicalBytes() || hex.EncodeToString(logical.Sum(nil)) != f.logicalSHA() || encoded.N != j.Result.Object.Bytes || hex.EncodeToString(encoded.H.Sum(nil)) != j.Result.Object.SHA256 {
		return ErrIntegrity
	}
	// The server's deferred Finish can commit just after the final response byte.
	// Poll only the same job status; never repeat the download or charge.
	return nil
}

// The coordinator is a distinct executable with its own exact-run credentials.
// It never inherits the test harness's operator profile or the API task role.
// Check local artifacts before consuming a one-shot cloud-flow claim.
func privateExecutablePreflight(path, hash string) error {
	if !filepath.IsAbs(path) || !opaque(hash) {
		return ErrInvalid
	}
	v := VerifierProcess{Executable: path, BinarySHA: hash}
	binary, err := v.openBinary()
	if err != nil {
		return err
	}
	defer binary.Close()
	_, err = v.execPath(binary)
	return err
}

func startPrivateUploadConsumer(ctx context.Context, run PrivateAPIRun, verifier VerifierProcess) (<-chan error, error) {
	path, sha := os.Getenv("CSV_PRIVATE_COORDINATOR_PATH"), os.Getenv("CSV_PRIVATE_COORDINATOR_SHA")
	if !filepath.IsAbs(path) || !opaque(sha) {
		return nil, ErrInvalid
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, ErrInvalid
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(file, 64<<20+1))
	file.Close()
	if e != nil || n > 64<<20 || hex.EncodeToString(h.Sum(nil)) != sha {
		return nil, ErrIntegrity
	}
	var cred struct {
		AccessKeyID, SecretAccessKey, SessionToken string
		Expires                                    time.Time
	}
	if jsonwire.Decode([]byte(os.Getenv("CSV_PRIVATE_COORDINATOR_CREDENTIALS")), &cred, 8192) != nil || cred.SessionToken == "" || cred.Expires.Before(time.Now().Add(11*time.Minute)) {
		return nil, ErrInvalid
	}
	v, e := verifier.Credentials.Retrieve(ctx)
	if e != nil {
		return nil, ErrUnknown
	}
	in := struct {
		Run                       PrivateAPIRun
		VerifierPath, VerifierSHA string
		ProofKey                  []byte
		VerifierCredentials       struct {
			AccessKeyID, SecretAccessKey, SessionToken string
			Expires                                    time.Time
		}
	}{Run: run, VerifierPath: verifier.Executable, VerifierSHA: verifier.BinarySHA, ProofKey: verifier.Key}
	in.VerifierCredentials.AccessKeyID = v.AccessKeyID
	in.VerifierCredentials.SecretAccessKey = v.SecretAccessKey
	in.VerifierCredentials.SessionToken = v.SessionToken
	in.VerifierCredentials.Expires = v.Expires
	raw, e := json.Marshal(in)
	if e != nil {
		return nil, ErrInvalid
	}
	child := exec.CommandContext(ctx, path)
	child.Env = []string{"AWS_REGION=us-east-2", "AWS_ACCESS_KEY_ID=" + cred.AccessKeyID, "AWS_SECRET_ACCESS_KEY=" + cred.SecretAccessKey, "AWS_SESSION_TOKEN=" + cred.SessionToken}
	child.Stdin = bytes.NewReader(raw)
	stdout, e := child.StdoutPipe()
	if e != nil {
		return nil, ErrUnknown
	}
	child.Stderr = io.Discard
	if e = child.Start(); e != nil {
		return nil, ErrUnknown
	}
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	e = awaitPrivateUploadReady(readyCtx, stdout, run.ID)
	cancel()
	if e != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		stdout.Close()
		clear(raw)
		return nil, e
	}
	done := make(chan error, 1)
	go func() { e := child.Wait(); clear(raw); done <- e }()
	return done, nil
}

func (f privateHTTPFixtureData) logicalBytes() int64 {
	if f.ExpectedBytes != 0 {
		return f.ExpectedBytes
	}
	return int64(len(f.Expected))
}
func (f privateHTTPFixtureData) logicalSHA() string {
	if f.ExpectedSHA != "" {
		return f.ExpectedSHA
	}
	return Hash(f.Expected)
}
func (f privateHTTPFixtureData) partCount() int {
	if len(f.Parts) == 0 {
		return len(f.Request.Files)
	}
	n := 0
	for _, parts := range f.Parts {
		n += len(parts)
	}
	return n
}
func (f privateHTTPFixtureData) part(slot string, number int32) (Part, int64, bool) {
	parts := f.Parts[slot]
	if len(parts) == 0 {
		for _, file := range f.Request.Files {
			if file.Slot == slot && number == 1 {
				return Part{Number: 1, Bytes: file.Bytes, SHA256: file.SHA256}, 0, true
			}
		}
		return Part{}, 0, false
	}
	offset := int64(0)
	for _, part := range parts {
		if part.Number == number {
			return part, offset, true
		}
		offset += part.Bytes
	}
	return Part{}, 0, false
}
func (f privateHTTPFixtureData) open(slot string, offset, n int64) (io.ReadCloser, error) {
	if f.Open != nil {
		return f.Open(slot, offset, n)
	}
	data, ok := f.Inputs[slot]
	if !ok || offset < 0 || n <= 0 || offset+n > int64(len(data)) {
		return nil, ErrInvalid
	}
	return io.NopCloser(bytes.NewReader(data[offset : offset+n])), nil
}

func awaitPrivateUploadReady(ctx context.Context, r io.Reader, run string) error {
	if !opaque(run) {
		return ErrInvalid
	}
	observed := make(chan string, 1)
	go func() {
		line, e := bufio.NewReader(io.LimitReader(r, 128)).ReadString('\n')
		if e != nil {
			observed <- ""
		} else {
			observed <- line
		}
	}()
	select {
	case <-ctx.Done():
		return ErrUnknown
	case line := <-observed:
		if line != "CSV_UPLOAD_READY "+run+"\n" {
			return ErrIntegrity
		}
		return nil
	}
}

func (a privateAPIClient) preflight(ctx context.Context, run string) error {
	for _, key := range []string{"", ID()} {
		req, e := http.NewRequestWithContext(ctx, "GET", "https://api.utils.bot/csv/jobs/"+run, nil)
		if e != nil {
			return ErrInvalid
		}
		if key != "" {
			req.Header.Set("X-CSV-Test-Key", key)
		}
		resp, e := a.HTTP.Do(req)
		if e != nil {
			return ErrUnknown
		}
		_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if e != nil || resp.StatusCode != 403 || resp.Header.Get("X-CSV-Payment-Mode") != "" {
			return ErrIntegrity
		}
	}
	// A real payment header is rejected before a route/backend/provider call.
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.utils.bot/csv/jobs/"+run+"/payment", strings.NewReader(`{"mode":"synthetic-no-funds"}`))
	if e != nil {
		return ErrInvalid
	}
	req.Header.Set("X-CSV-Test-Key", a.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Payment-Signature", "synthetic-invalid-do-not-settle")
	resp, e := a.HTTP.Do(req)
	if e != nil {
		return ErrUnknown
	}
	defer resp.Body.Close()
	if _, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); e != nil || resp.StatusCode != 400 {
		return ErrIntegrity
	}
	return nil
}
