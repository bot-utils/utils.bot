package tabular

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

var streamCaps = StreamLimits{InputBytes: 1 << 30, OutputBytes: 2 << 30, Rows: 10_000_000}

func TestStreamMatchesRequestContract(t *testing.T) {
	inputs := []string{"id,v\n01,  HeLLo  \n02,\"aaa,$1\nx\"\n03,ÉΣİß\n04,\"\"\n", "v\r\n\"a\r\nb\"\r\n", "v\n", "\"\ufeff\",v\n01,x\n"}
	for _, input := range inputs {
		for _, op := range []string{"trim", "lower", "upper", "replace"} {
			raw, _ := json.Marshal(map[string]string{"column": "v", "op": op})
			if op == "replace" {
				raw, _ = json.Marshal(map[string]string{"column": "v", "op": op, "old": "aa", "new": "$1\\"})
			}
			want, e := Execute("transform", raw, map[string][]byte{"file": []byte(input)})
			if e != nil {
				t.Fatal(e)
			}
			var out bytes.Buffer
			stats, e := StreamTransform(strings.NewReader(input), &out, raw, streamCaps)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := csv.NewReader(&out).ReadAll()
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(decoded[0], want.Columns) || !reflect.DeepEqual(decoded[1:], want.Rows) || stats.Rows != want.OutputRows || stats.InputBytes != int64(len(input)) {
				t.Fatal(op, stats, decoded, want)
			}
		}
	}
}
func TestStreamLimitsAndInvalidData(t *testing.T) {
	raw := json.RawMessage(`{"column":"v","op":"upper"}`)
	input := "v\na\nb\n"
	var valid bytes.Buffer
	stats, e := StreamTransform(strings.NewReader(input), &valid, raw, streamCaps)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		input string
		cap   StreamLimits
		code  string
	}{
		{input, StreamLimits{int64(len(input)), stats.OutputBytes, 2}, ""},
		{input, StreamLimits{int64(len(input) - 1), stats.OutputBytes, 2}, "file_limit"},
		{input, StreamLimits{int64(len(input)), stats.OutputBytes - 1, 2}, "output_byte_limit"},
		{input, StreamLimits{1 << 20, 1 << 20, 1}, "row_limit"},
		{"\ufeffv\nx\n", streamCaps, "invalid_csv"}, {"v\na\x00\n", streamCaps, "invalid_csv"},
		{"v\n\xff\n", streamCaps, "invalid_csv"}, {"v,v\na,b\n", streamCaps, "invalid_header"},
		{"v\n\"unfinished", streamCaps, "invalid_csv"}, {"v\n" + strings.Repeat("x", MaxCell+1) + "\n", streamCaps, "cell_limit"},
		{"v\n" + strings.Repeat("ȿ", MaxCell/3+1) + "\n", streamCaps, "cell_limit"},
	} {
		var out bytes.Buffer
		got, e := StreamTransform(strings.NewReader(tc.input), &out, raw, tc.cap)
		if tc.code == "" {
			if e != nil {
				t.Fatal(e)
			}
			continue
		}
		if e == nil || e.Error() != tc.code || got != (StreamStats{}) {
			t.Fatalf("wanted %s: %#v %v", tc.code, got, e)
		}
	}
}

type failOutput struct{}

func (failOutput) Write([]byte) (int, error) { return 0, errors.New("PRIVATE_DISK_FULL") }
func TestStreamDiskFullIsSanitized(t *testing.T) {
	stats, e := StreamTransform(strings.NewReader("v\nx\n"), failOutput{}, json.RawMessage(`{"column":"v","op":"trim"}`), streamCaps)
	if e == nil || e.Error() != "output_unavailable" || stats != (StreamStats{}) {
		t.Fatal(stats, e)
	}
}

type endlessInput struct{ reads int }

func (r *endlessInput) Read(p []byte) (int, error) {
	r.reads += len(p)
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
func TestStreamBoundsMalformedRecordBeforeMaterializing(t *testing.T) {
	source := &endlessInput{}
	_, e := StreamTransform(io.MultiReader(strings.NewReader("v\n\""), source), io.Discard, json.RawMessage(`{"column":"v","op":"trim"}`), streamCaps)
	if e == nil || e.Error() != "cell_limit" || source.reads > 96<<10 {
		t.Fatal(source.reads, e)
	}
}

func TestStreamMaximumQuotedFieldsAndColumnWidth(t *testing.T) {
	header := make([]string, MaxColumns)
	row := make([]string, MaxColumns)
	for i := range header {
		header[i] = fmt.Sprintf("c%d", i)
		row[i] = strings.Repeat("\"", MaxCell)
	}
	var input bytes.Buffer
	writer := csv.NewWriter(&input)
	_ = writer.Write(header)
	_ = writer.Write(row)
	writer.Flush()
	raw, _ := json.Marshal(map[string]string{"column": header[MaxColumns-1], "op": "trim"})
	var out bytes.Buffer
	stats, e := StreamTransform(bytes.NewReader(input.Bytes()), &out, raw, streamCaps)
	if e != nil || stats.Rows != 1 {
		t.Fatal(stats, e)
	}
	decoded, e := csv.NewReader(&out).ReadAll()
	if e != nil || !reflect.DeepEqual(decoded[1], row) {
		t.Fatal("maximum valid quoted row rejected", e)
	}
}
