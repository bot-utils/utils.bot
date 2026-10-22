package csvwire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	tabular "pdfservice/internal/csvtabular"
	"strings"
	"testing"
)

func fixture(t *testing.T, op, options string, data map[string]string) (Request, map[string]io.Reader) {
	t.Helper()
	canon, e := tabular.CanonicalOptions(op, json.RawMessage(options))
	if e != nil {
		t.Fatal(e)
	}
	q := Request{Version: 1, Operation: op, Options: canon}
	slots := []string{"file"}
	if op == "join" {
		slots = []string{"left", "right"}
	}
	inputs := map[string]io.Reader{}
	for _, slot := range slots {
		p := data[slot]
		q.Files = append(q.Files, File{Slot: slot, Bytes: int64(len(p)), SHA256: hash([]byte(p))})
		inputs[slot] = strings.NewReader(p)
	}
	return q, inputs
}
func TestAllFourOperationsPrivateFraming(t *testing.T) {
	tests := []struct {
		op, opts, expected string
		data               map[string]string
	}{
		{"dedupe", `{"key_columns":["id"],"keep":"first"}`, "id,v\n1,a\n2,c\n", map[string]string{"file": "id,v\n1,a\n1,b\n2,c\n"}},
		{"join", `{"left_key_columns":["id"],"right_key_columns":["id"],"type":"inner"}`, "id,v,x\n1,a,z\n", map[string]string{"left": "id,v\n1,a\n2,b\n", "right": "id,x\n1,z\n"}},
		{"aggregate", `{"group_columns":[],"metrics":[{"name":"n","op":"count_rows"}]}`, "n\n2\n", map[string]string{"file": "id,v\n1,a\n2,b\n"}},
		{"transform", `{"column":"v","op":"upper"}`, "id,v\n1,A\n2,B\n", map[string]string{"file": "id,v\n1,a\n2,b\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			q, in := fixture(t, tt.op, tt.opts, tt.data)
			var request, result, encoded bytes.Buffer
			if e := WriteRequest(&request, q, in); e != nil {
				t.Fatal(e)
			}
			if e := Process(&request, &result); e != nil {
				t.Fatal(e)
			}
			m, e := ReadResult(&result, &encoded)
			if e != nil {
				t.Fatal(e)
			}
			if m.LogicalSHA256 != hash([]byte(tt.expected)) {
				t.Fatal("independent expected output differs")
			}
			if VerifyResult(m, encoded.Bytes()) != nil {
				t.Fatal("result recheck")
			}
		})
	}
}
func TestWireRejectsTruncationOverrunAmbiguityAndInvalidOptions(t *testing.T) {
	q, in := fixture(t, "transform", `{"column":"v","op":"trim"}`, map[string]string{"file": "id,v\n1,a\n"})
	var good bytes.Buffer
	if WriteRequest(&good, q, in) != nil {
		t.Fatal("fixture")
	}
	raw := good.Bytes()
	for _, v := range [][]byte{raw[:3], raw[:len(raw)-1], append(append([]byte{}, raw...), 1)} {
		var out bytes.Buffer
		if Process(bytes.NewReader(v), &out) == nil || out.Len() != 0 {
			t.Fatal("bad input published")
		}
	}
	var b bytes.Buffer
	bad := q
	bad.Options = json.RawMessage(`{"column":"v","op":"eval","code":"secret"}`)
	if WriteRequest(&b, bad, map[string]io.Reader{"file": strings.NewReader("id,v\n1,a\n")}) != ErrWire || b.Len() != 0 {
		t.Fatal("executable options accepted")
	}
	in[q.Files[0].Slot] = strings.NewReader("id,v\n1,a\nX")
	if WriteRequest(io.Discard, q, in) != ErrWire {
		t.Fatal("extra source accepted")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxHeader+1)
	if Process(bytes.NewReader(hdr[:]), io.Discard) != ErrWire {
		t.Fatal("unbounded frame")
	}
	body := []byte(`{"Version":1,"operation":"transform","options":{},"files":[]}`)
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if Process(bytes.NewReader(append(hdr[:], body...)), io.Discard) != ErrWire {
		t.Fatal("case-folded header")
	}
}
func TestForgedResultCannotLeakPartialBytes(t *testing.T) {
	q, in := fixture(t, "transform", `{"column":"v","op":"trim"}`, map[string]string{"file": "id,v\n1,a\n"})
	var request, result bytes.Buffer
	_ = WriteRequest(&request, q, in)
	_ = Process(&request, &result)
	raw := result.Bytes()
	for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte{}, raw...), 1)} {
		var sink bytes.Buffer
		if _, e := ReadResult(bytes.NewReader(bad), &sink); e == nil || sink.Len() != 0 {
			t.Fatal("corrupt result committed")
		}
	}
}

func TestPrivateJoinSupportsFullOutputWidthWithoutWideningInputs(t *testing.T) {
	left, right := []string{"id"}, []string{"id"}
	for i := 1; i < 128; i++ {
		left = append(left, fmt.Sprint("l", i))
		right = append(right, fmt.Sprint("r", i))
	}
	data := map[string]string{"left": strings.Join(left, ",") + "\n", "right": strings.Join(right, ",") + "\n"}
	q, in := fixture(t, "join", `{"left_key_columns":["id"],"right_key_columns":["id"],"type":"inner"}`, data)
	var request, result, sink bytes.Buffer
	if WriteRequest(&request, q, in) != nil || Process(&request, &result) != nil {
		t.Fatal("wide join fixture")
	}
	if _, e := ReadResult(&result, &sink); e != nil {
		t.Fatal("valid 255-column joined result rejected", e)
	}
	if _, e := tabular.ReadCSV([]byte(strings.Join(append(left, "too-wide"), ",") + "\n")); e == nil {
		t.Fatal("input width widened")
	}
}
