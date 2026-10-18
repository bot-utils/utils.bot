package jsonwire

import (
	"strings"
	"testing"
)

func TestRejectAmbiguousAndUnboundedControlJSON(t *testing.T) {
	for _, raw := range []string{
		`{"pass":true,"pass":false}`, `{"pass":true,"PASS":false}`,
		`{"payload":{"value":"1","Value":"2"}}`, `{} {}`,
		string([]byte{'"', 0xff, '"'}), strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34),
		"[" + strings.Repeat("0,", 4096) + "0]",
	} {
		var result any
		if Unmarshal([]byte(raw), &result, 1<<20) == nil {
			t.Fatal("invalid control JSON accepted")
		}
	}
	var out struct {
		Pass bool `json:"pass"`
	}
	if Decode([]byte(`{"pass":true,"other":1}`), &out, 100) == nil {
		t.Fatal("unknown private field accepted")
	}
	if Decode([]byte(`{"pass":true}`), &out, 5) == nil {
		t.Fatal("oversized message accepted")
	}
	if Decode([]byte(`{"pass":true}`), &out, 100) != nil || !out.Pass {
		t.Fatal("valid response rejected")
	}
}
