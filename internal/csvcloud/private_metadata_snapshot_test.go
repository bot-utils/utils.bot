package csvcloud

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"pdfservice/internal/csvwire"
)

// Operator-supplied synthetic metadata is replayed entirely in memory with dummy
// signing credentials. This test makes no AWS request and never prints rows.
func TestPrivateStoredMetadataReplayLocal(t *testing.T) {
	var snapshot struct {
		RunID   string
		Until   int64
		Request csvwire.Request
		Items   []map[string]map[string]string
	}
	raw := os.Getenv("CSV_PRIVATE_METADATA_SNAPSHOT")
	if raw == "" {
		t.Skip("explicit synthetic metadata snapshot required")
	}
	if json.Unmarshal([]byte(raw), &snapshot) != nil || snapshot.RunID != os.Getenv("CSV_PRIVATE_METADATA_VALIDATE") || !opaque(snapshot.RunID) {
		t.Fatal("invalid snapshot gate")
	}
	f := newPrivateBackendFixture(t)
	f.b.RunID = snapshot.RunID
	f.b.Request = snapshot.Request
	f.b.Until = snapshot.Until
	f.b.Repo.Table = "utils-bot-csv-private-" + snapshot.RunID[:16]
	f.b.Objects.Account = "999999999999"
	f.b.Objects.Bucket = "utils-csv-999999999999-" + snapshot.RunID[:24]
	f.b.Queue.Repo = f.b.Repo
	f.b.Queue.URL = "https://sqs.us-east-2.amazonaws.com/999999999999/" + f.b.Repo.Table
	f.db.rows = map[string]map[string]d.AttributeValue{}
	for _, item := range snapshot.Items {
		row := map[string]d.AttributeValue{}
		for key, value := range item {
			if s, ok := value["S"]; ok {
				row[key] = &d.AttributeValueMemberS{Value: s}
			} else if n, ok := value["N"]; ok {
				row[key] = &d.AttributeValueMemberN{Value: n}
			} else if b, ok := value["B"]; ok {
				decoded, e := base64.StdEncoding.DecodeString(b)
				if e != nil {
					t.Fatal("invalid snapshot encoding")
				}
				row[key] = &d.AttributeValueMemberB{Value: decoded}
			} else {
				t.Fatal("unexpected snapshot attribute")
			}
		}
		f.db.rows[avs(row["pk"])] = row
	}
	job, e := f.b.Repo.Get(ctx, snapshot.RunID)
	if e != nil || job == nil {
		t.Fatal("stored job invalid", e)
	}
	f.b.Now = func() time.Time { return time.Unix(job.UploadUntil-1, 0) }
	for _, object := range job.Inputs {
		if _, e := f.b.upload(ctx, object); e != nil {
			t.Fatal("stored upload metadata invalid", e)
		}
	}
	result, e := f.b.Begin(ctx, f.b.Request)
	if e != nil || result.JobID != snapshot.RunID || len(result.Parts) != len(job.Inputs) || f.creates != 0 || len(f.db.transactions) != 0 || f.queue.calls != 0 {
		t.Fatal("stored admission replay failed", e)
	}
	t.Log("Stored metadata and admission replay verified locally; no AWS requests, writes, uploads or compute.")
}
