package csvwire

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	tabular "pdfservice/internal/csvtabular"
	"testing"
)

func TestStreamTransformWireAndIndependentOracle(t *testing.T) {
	input := []byte("id,value,other\n1,old,keep\n2,\"old,old\",\"line\nbreak\"\n3,older,unchanged\n")
	want := []byte("id,value,other\n1,new,keep\n2,\"new,new\",\"line\nbreak\"\n3,newer,unchanged\n")
	options, e := tabular.CanonicalOptions("transform", json.RawMessage(`{"column":"value","op":"replace","old":"old","new":"new"}`))
	if e != nil {
		t.Fatal(e)
	}
	q := Request{Version: 2, Operation: "transform", Options: options, Files: []File{{Slot: "file", Bytes: int64(len(input)), SHA256: hash(input)}}}
	var request, result bytes.Buffer
	if WriteRequest(&request, q, map[string]io.Reader{"file": bytes.NewReader(input)}) != nil {
		t.Fatal("request")
	}
	spool, e := os.CreateTemp(t.TempDir(), "spool")
	if e != nil {
		t.Fatal(e)
	}
	defer spool.Close()
	if e = ProcessStream(&request, &result, spool); e != nil {
		t.Fatal(e)
	}
	var encoded bytes.Buffer
	m, e := ReadStreamResult(&result, &encoded)
	if e != nil || m.LogicalBytes != int64(len(want)) || m.LogicalSHA256 != hash(want) || m.Rows != 3 {
		t.Fatal("independent transform oracle", e)
	}
	if VerifyStreamResult(m, bytes.NewReader(encoded.Bytes())) != nil {
		t.Fatal("verification")
	}
	for _, change := range []string{"hash", "rows", "logical-length", "trailing", "truncated", "second-member"} {
		t.Run(change, func(t *testing.T) {
			bad := m
			data := append([]byte(nil), encoded.Bytes()...)
			switch change {
			case "hash":
				bad.LogicalSHA256 = hash(nil)
			case "rows":
				bad.Rows++
			case "logical-length":
				bad.LogicalBytes++
			case "trailing":
				data = append(data, 0)
				bad.EncodedBytes++
				bad.EncodedSHA256 = hash(data)
			case "truncated":
				data = data[:len(data)-1]
				bad.EncodedBytes--
				bad.EncodedSHA256 = hash(data)
			case "second-member":
				data = append(data, data...)
				bad.EncodedBytes *= 2
				bad.EncodedSHA256 = hash(data)
			}
			if VerifyStreamResult(bad, bytes.NewReader(data)) == nil {
				t.Fatal("corrupt stream accepted")
			}
		})
	}
}
func TestStreamProfileCannotEnterV1Allocator(t *testing.T) {
	opts, _ := tabular.CanonicalOptions("transform", json.RawMessage(`{"column":"v","op":"upper"}`))
	q := Request{Version: 2, Operation: "transform", Options: opts, Files: []File{{Slot: "file", Bytes: MaxStreamBytes, SHA256: hash(nil)}}}
	if q.Validate() != nil {
		t.Fatal("large metadata rejected")
	}
	var frame bytes.Buffer
	_ = writeFrame(&frame, q)
	if _, _, e := readRequest(&frame); e == nil {
		t.Fatal("v2 reached whole-file allocator")
	}
	q.Version = 1
	if q.Validate() == nil {
		t.Fatal("v1 cap relaxed")
	}
	q.Version = 2
	q.Operation = "dedupe"
	if q.Validate() == nil {
		t.Fatal("unimplemented streaming operation accepted")
	}
	m := Result{Version: 2, EncodedBytes: MaxStreamBytes, LogicalBytes: MaxStreamBytes, Rows: 1, EncodedSHA256: hash(nil), LogicalSHA256: hash(nil)}
	frame.Reset()
	_ = writeFrame(&frame, m)
	if _, e := ReadResult(&frame, io.Discard); e == nil {
		t.Fatal("v2 reached encoded-file allocator")
	}
}
