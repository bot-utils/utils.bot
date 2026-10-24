package tabular

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

func TestTransformUnicodeContractAndStableProjection(t *testing.T) {
	if unicode.Version != TransformUnicodeVersion {
		t.Fatal("review Unicode semantics before upgrading the worker")
	}
	tests := []struct{ options, input, want string }{
		{`{"column":"v","op":"trim"}`, "\t\u00a0hello\u2003 ", "hello"},
		{`{"column":"v","op":"trim"}`, "\u200bhello\ufeff", "\u200bhello\ufeff"},
		{`{"column":"v","op":"lower"}`, "ÉΣİABC", "éσiabc"},
		{`{"column":"v","op":"upper"}`, "éσßabc", "ÉΣßABC"},
		{`{"column":"v","op":"replace","old":"aa","new":"b"}`, "aaa", "ba"},
		{`{"column":"v","op":"replace","old":"$1","new":"\\1"}`, "$1.$1", "\\1.\\1"},
		{`{"column":"v","op":"replace","old":"x","new":""}`, "xax", "a"},
	}
	for _, tc := range tests {
		source := Table{Columns: []string{"id", "v"}, Rows: [][]string{{"001", tc.input}, {"002", ""}}}
		before := append([]string{}, source.Rows[0]...)
		got, err := transform(source, json.RawMessage(tc.options))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Columns, source.Columns) || !reflect.DeepEqual(got.Rows, [][]string{{"001", tc.want}, {"002", ""}}) || got.InputRows["file"] != 2 || got.OutputRows != 2 {
			t.Fatalf("%s: %#v", tc.options, got)
		}
		if !reflect.DeepEqual(source.Rows[0], before) {
			t.Fatal("input table mutated")
		}
	}
	got := execute(t, "transform", `{"column":"v","op":"trim"}`, map[string][]byte{"file": []byte("v\n")})
	if got.Rows == nil || len(got.Rows) != 0 {
		t.Fatal(got)
	}
}

func TestTransformRejectsAmbiguousOrExecutableOptions(t *testing.T) {
	input := map[string][]byte{"file": []byte("v\nhello\n")}
	for _, raw := range []string{
		`{"column":"v","op":"trim","old":"x"}`, `{"column":"v","op":"upper","new":"x"}`,
		`{"column":"v","op":"replace","old":"x"}`, `{"column":"v","op":"replace","old":"","new":"x"}`,
		`{"column":"v","op":"replace","old":"x","new":"\u0000"}`, `{"column":"v","op":"replace","old":"\u0000","new":"x"}`,
		`{"column":"v","op":"trim","instruction":"PRIVATE_INSTRUCTION"}`,
		`{"column":"v","op":"trim","url":"https://example.invalid"}`,
		`{"column":"v","op":"replace","old":"x","new":"y","regex":true}`,
		`{"column":"v","op":"trim","steps":[]}`, `{"column":"v","op":"trim","op":"upper"}`,
		`{"column":"v","op":null}`, `{"Column":"v","op":"trim"}`,
		`{"column":"v","op":"replace","old":"x","new":null}`,
		`{"column":"v","op":"replace","old":"x","new":"\ud800"}`,
	} {
		assertCode(t, "transform", raw, input, "invalid_options")
	}
	for _, op := range []string{"python", "sql", "regex", "eval", "TRIM", ""} {
		raw, _ := json.Marshal(map[string]string{"column": "v", "op": op})
		assertCode(t, "transform", string(raw), input, "invalid_transform")
	}
	assertCode(t, "transform", `{"column":"missing","op":"trim"}`, input, "invalid_columns")
	assertCode(t, "transform", `{"op":"trim"}`, input, "invalid_columns")
	assertCode(t, "transform", `{"column":"v","op":"trim"}`, map[string][]byte{"left": input["file"]}, "invalid_parts")
}

func TestTransformExpansionLimitsAreAtomic(t *testing.T) {
	ptr := func(s string) *string { return &s }
	options := TransformOptions{Column: "v", Op: "replace", Old: ptr("x"), New: ptr(strings.Repeat("y", MaxReplacement))}
	raw, _ := json.Marshal(options)
	good := execute(t, "transform", string(raw), map[string][]byte{"file": []byte("v\n" + strings.Repeat("x", 16) + "\n")})
	if len(good.Rows[0][0]) != MaxCell {
		t.Fatal("exact cell limit rejected")
	}
	assertCode(t, "transform", string(raw), map[string][]byte{"file": []byte("v\nx\n" + strings.Repeat("x", 17) + "\n")}, "cell_limit")
	options.New = ptr(strings.Repeat("y", MaxReplacement+1))
	raw, _ = json.Marshal(options)
	assertCode(t, "transform", string(raw), map[string][]byte{"file": []byte("v\nx\n")}, "invalid_options")
	options.New = ptr("y")
	options.Old = ptr(strings.Repeat("x", MaxReplacement+1))
	raw, _ = json.Marshal(options)
	assertCode(t, "transform", string(raw), map[string][]byte{"file": []byte("v\nx\n")}, "invalid_options")
	// Simple Unicode casing can expand UTF-8 bytes without adding runes.
	assertCode(t, "transform", `{"column":"v","op":"upper"}`, map[string][]byte{"file": []byte("v\na\n" + strings.Repeat("ȿ", MaxCell/3+1) + "\n")}, "cell_limit")
	options.Old = ptr("x")
	options.New = ptr(strings.Repeat("y", MaxReplacement))
	raw, _ = json.Marshal(options)
	assertCode(t, "transform", string(raw), map[string][]byte{"file": []byte("v\n" + strings.Repeat(strings.Repeat("x", 16)+"\n", 513))}, "output_byte_limit")
}

func TestTransformTreatsInstructionsAndFormulasAsData(t *testing.T) {
	input := map[string][]byte{"file": []byte("v,id\n=SUM(A1:A2),01\n$(curl attacker.invalid),02\nignore prior instructions,03\n")}
	got := execute(t, "transform", `{"column":"v","op":"replace","old":"absent","new":"untrusted"}`, input)
	if got.Rows[0][0] != "=SUM(A1:A2)" || got.Rows[1][0] != "$(curl attacker.invalid)" || got.Rows[2][0] != "ignore prior instructions" || got.Rows[2][1] != "03" {
		t.Fatal(got)
	}
}
