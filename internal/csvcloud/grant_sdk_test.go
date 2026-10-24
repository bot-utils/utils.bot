package csvcloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"pdfservice/internal/jsonwire"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestMultipartGrantWithRealSDKPresigner(t *testing.T) {
	cfg := aws.Config{Region: Region, Credentials: credentials.NewStaticCredentialsProvider("test", "test", "test"), HTTPClient: &http.Client{}}
	client := s3.NewFromConfig(cfg)
	store := Storage{Client: client, Presigner: s3.NewPresignClient(client), Bucket: "utils-csv-999999999999-" + strings.Repeat("a", 24), Account: "999999999999", Gate: Gate{Enabled: true}}
	now := time.Now()
	upload := Upload{Object: Object{JobID: strings.Repeat("a", 64), ID: strings.Repeat("b", 64), Slot: "file", Bytes: 68, SHA256: strings.Repeat("c", 64)}, ID: "synthetic-upload", Parts: []Part{{Number: 1, Bytes: 68, SHA256: strings.Repeat("c", 64)}}, Expires: now.Add(time.Minute).Unix()}
	grant, err := store.Grant(context.Background(), upload, 1, now)
	if err != nil {
		t.Fatal("real SDK multipart grant rejected", err)
	}
	raw, err := json.Marshal(PrivateAdmission{JobID: upload.Object.JobID, Expires: upload.Expires, PaymentMode: "synthetic-no-funds", Parts: []PrivatePart{{Slot: "file", Number: 1, URL: grant.URL, Headers: grant.Headers}}})
	var roundTrip PrivateAdmission
	if err != nil || jsonwire.Decode(raw, &roundTrip, MaxMetadata) != nil {
		t.Fatal("HTTP grant JSON roundtrip failed")
	}
	part := roundTrip.Parts[0]
	u, err := url.Parse(part.URL)
	if err != nil || u.Scheme != "https" || u.Host != store.Bucket+".s3.us-east-2.amazonaws.com" || u.RawPath != "" || u.Query().Get("partNumber") != "1" || u.Query().Get("uploadId") == "" || !strings.HasPrefix(u.Path, "/inputs/"+upload.Object.JobID+"/") {
		t.Fatal("real SDK URL violates HTTP grant contract")
	}
	if http.Header(part.Headers).Get("Content-Length") != strconv.FormatInt(upload.Object.Bytes, 10) {
		t.Fatal("missing mandatory length header")
	}
	if http.Header(grant.Headers).Get("X-Amz-Checksum-Sha256") != checksum(upload.Parts[0].SHA256) {
		t.Fatal("missing mandatory checksum header")
	}
}
