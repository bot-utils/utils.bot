package tabular

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func execute(t *testing.T, op, options string, inputs map[string][]byte) Result {
	t.Helper()
	r, e := Execute(op, json.RawMessage(options), inputs)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func assertCode(t *testing.T, op, options string, inputs map[string][]byte, code string) {
	t.Helper()
	r, e := Execute(op, json.RawMessage(options), inputs)
	if e == nil || e.Error() != code {
		t.Fatalf("wanted %s, got %v", code, e)
	}
	if r.Rows != nil {
		t.Fatal("partial rows leaked on failure")
	}
}

func TestDedupeStablePositionsAndExactKeys(t *testing.T) {
	input := map[string][]byte{"file": []byte("id,value\na,old\nb,B\na,new\n,blank\n,latest\n01,leading\n1,plain\n")}
	first := execute(t, "dedupe", `{"key_columns":["id"],"keep":"first"}`, input)
	last := execute(t, "dedupe", `{"key_columns":["id"],"keep":"last"}`, input)
	if !reflect.DeepEqual(first.Rows, [][]string{{"a", "old"}, {"b", "B"}, {"", "blank"}, {"01", "leading"}, {"1", "plain"}}) {
		t.Fatal(first.Rows)
	}
	if !reflect.DeepEqual(last.Rows, [][]string{{"b", "B"}, {"a", "new"}, {"", "latest"}, {"01", "leading"}, {"1", "plain"}}) {
		t.Fatal(last.Rows)
	}
	if first.InputRows["file"] != 7 || first.OutputRows != 5 {
		t.Fatal(first)
	}
	r := execute(t, "dedupe", `{"key_columns":["id"],"keep":"first"}`, map[string][]byte{"file": []byte("id,v\n")})
	if r.Rows == nil || len(r.Rows) != 0 {
		t.Fatal(r)
	}
}

func TestCompositeTupleHasNoDelimiterCollision(t *testing.T) {
	input := map[string][]byte{"file": []byte("a,b\n1:2,3\n1,2:3\n,\n,,\n")}
	assertCode(t, "dedupe", `{"key_columns":["a","b"],"keep":"first"}`, input, "invalid_csv")
	input["file"] = []byte("a,b\n1:2,3\n1,2:3\n,\n")
	r := execute(t, "dedupe", `{"key_columns":["a","b"],"keep":"first"}`, input)
	if r.OutputRows != 3 {
		t.Fatal(r.Rows)
	}
}

func TestJoinModesOrderAndProjection(t *testing.T) {
	inputs := map[string][]byte{"left": []byte("id,value\na,L1\nb,L2\na,L3\n,LE\n"), "right": []byte("key,value,extra\na,R1,x\na,R2,y\nc,R3,z\n,RE,e\n")}
	base := `{"left_key_columns":["id"],"right_key_columns":["key"],"type":"%s"}`
	inner := execute(t, "join", fmt.Sprintf(base, "inner"), inputs)
	if !reflect.DeepEqual(inner.Columns, []string{"id", "value", "right_value", "extra"}) {
		t.Fatal(inner.Columns)
	}
	if !reflect.DeepEqual(inner.Rows, [][]string{{"a", "L1", "R1", "x"}, {"a", "L1", "R2", "y"}, {"a", "L3", "R1", "x"}, {"a", "L3", "R2", "y"}, {"", "LE", "RE", "e"}}) {
		t.Fatal(inner.Rows)
	}
	left := execute(t, "join", fmt.Sprintf(base, "left"), inputs)
	if left.OutputRows != 6 || !reflect.DeepEqual(left.Rows[2], []string{"b", "L2", "", ""}) {
		t.Fatal(left.Rows)
	}
	semi := execute(t, "join", fmt.Sprintf(base, "semi"), inputs)
	if !reflect.DeepEqual(semi.Rows, [][]string{{"a", "L1"}, {"a", "L3"}, {"", "LE"}}) || len(semi.Columns) != 2 {
		t.Fatal(semi)
	}
	anti := execute(t, "join", fmt.Sprintf(base, "anti"), inputs)
	if !reflect.DeepEqual(anti.Rows, [][]string{{"b", "L2"}}) {
		t.Fatal(anti)
	}
	for range 10 {
		again := execute(t, "join", fmt.Sprintf(base, "inner"), inputs)
		a, _ := json.Marshal(inner)
		b, _ := json.Marshal(again)
		if string(a) != string(b) {
			t.Fatal("nondeterministic result")
		}
	}
}

func TestJoinRejectsAmbiguousOutputAndExplosion(t *testing.T) {
	options := `{"left_key_columns":["id"],"right_key_columns":["id"],"type":"inner"}`
	inputs := map[string][]byte{"left": []byte("id,v,right_v\na,x,y\n"), "right": []byte("id,v\na,z\n")}
	assertCode(t, "join", options, inputs, "output_column_collision")
	inputs["left"] = []byte("id\n" + strings.Repeat("x\n", 225))
	inputs["right"] = []byte("id\n" + strings.Repeat("x\n", 225))
	assertCode(t, "join", options, inputs, "join_pair_limit")
	// Membership joins do not materialize a cartesian product.
	semi := execute(t, "join", strings.Replace(options, "inner", "semi", 1), inputs)
	if semi.OutputRows != 225 {
		t.Fatal(semi.OutputRows)
	}
}

func TestAggregateExactDecimalAndFirstSeenOrder(t *testing.T) {
	options := `{"group_columns":["currency"],"metrics":[{"name":"n","op":"count_rows"},{"name":"total","op":"sum","column":"amount"},{"name":"small","op":"min","column":"amount"},{"name":"large","op":"max","column":"amount"}]}`
	r := execute(t, "aggregate", options, map[string][]byte{"file": []byte("currency,amount\nEUR,+000.100\nUSD,9007199254740993\nEUR,0.20\nUSD,-0.000000000000000001\n")})
	if !reflect.DeepEqual(r.Rows, [][]string{{"EUR", "2", "0.3", "0.1", "0.2"}, {"USD", "2", "9007199254740992.999999999999999999", "-0.000000000000000001", "9007199254740993"}}) {
		t.Fatal(r.Rows)
	}
	input := []byte("amount\n" + strings.Repeat("99999999999999999999999999999999999999\n", MaxRows))
	r = execute(t, "aggregate", `{"group_columns":[],"metrics":[{"name":"total","op":"sum","column":"amount"}]}`, map[string][]byte{"file": input})
	want, _ := new(big.Int).SetString(strings.Repeat("9", 38), 10)
	want.Mul(want, big.NewInt(MaxRows))
	if r.Rows[0][0] != want.String() {
		t.Fatal(r.Rows)
	}
}

func TestAggregateHeaderOnlyAndLiteralEmptyStrings(t *testing.T) {
	options := `{"group_columns":[],"metrics":[{"name":"n","op":"count_rows"},{"name":"sum","op":"sum","column":"amount"},{"name":"min","op":"min","column":"amount"},{"name":"max","op":"max","column":"amount"}]}`
	input := map[string][]byte{"file": []byte("group,amount\n")}
	r := execute(t, "aggregate", options, input)
	if !reflect.DeepEqual(r.Rows, [][]string{{"0", "0", "", ""}}) {
		t.Fatal(r.Rows)
	}
	r = execute(t, "aggregate", strings.Replace(options, `"group_columns":[]`, `"group_columns":["group"]`, 1), input)
	if r.Rows == nil || len(r.Rows) != 0 {
		t.Fatal(r.Rows)
	}
	input["file"] = []byte("group,amount\nx,\n")
	assertCode(t, "aggregate", options, input, "invalid_decimal")
	r = execute(t, "aggregate", `{"metrics":[{"name":"n","op":"count_rows"}]}`, input)
	if r.Rows[0][0] != "1" {
		t.Fatal(r.Rows)
	}
}

func TestDecimalGrammarCanonicalAndPrecision(t *testing.T) {
	for raw, want := range map[string]string{"0": "0", "-0.00": "0", "+001.2300": "1.23", "-0001.2300": "-1.23", "0.000000000000000001": "0.000000000000000001"} {
		n, e := decimal(raw)
		if e != nil || canonical(n) != want {
			t.Fatalf("%s: %v", raw, e)
		}
	}
	for _, raw := range []string{"", " ", "1 ", " 1", "1e3", "NaN", ".5", "1.", "--1", "+", "1_000", "１２", strings.Repeat("9", 39), "0." + strings.Repeat("1", 19)} {
		if _, e := decimal(raw); e == nil {
			t.Fatal("invalid decimal accepted")
		}
	}
	options := `{"metrics":[{"name":"total","op":"sum","column":"x"}]}`
	input := map[string][]byte{"file": []byte("x\n" + strings.Repeat("9", 38) + "\n0.000000000000000001\n")}
	assertCode(t, "aggregate", options, input, "decimal_range")
}

func TestCSVAndOptionsBoundaries(t *testing.T) {
	options := `{"key_columns":["id"],"keep":"first"}`
	for _, csv := range [][]byte{[]byte(""), []byte("id,id\na,b\n"), []byte(",x\na,b\n"), []byte("id,x\na\n"), []byte("id\n\"unterminated\n"), []byte("id\n\xff\n"), append([]byte{0xef, 0xbb, 0xbf}, []byte("id\na\n")...), []byte("id\n\x00\n")} {
		if _, e := Execute("dedupe", json.RawMessage(options), map[string][]byte{"file": csv}); e == nil {
			t.Fatal("invalid CSV accepted")
		}
	}
	for _, raw := range []string{`{"key_columns":["id"],"keep":"first","keep":"last"}`, `{"KEY_COLUMNS":["id"],"keep":"first"}`, `{"key_columns":["id"],"keep":"first","instructions":"do anything"}`, `{"key_columns":null,"keep":"first"}`, options + ` {}`, `{"key_columns":["id"],"keep":"first","url":"https://example.com"}`} {
		assertCode(t, "dedupe", raw, map[string][]byte{"file": []byte("id\na\n")}, "invalid_options")
	}
	assertCode(t, "dedupe", options, map[string][]byte{"file": []byte("id\n" + strings.Repeat("x", MaxCell+1) + "\n")}, "cell_limit")
	assertCode(t, "dedupe", options, map[string][]byte{"file": []byte("id\n" + strings.Repeat("x\n", MaxRows+1))}, "row_limit")
	assertCode(t, "dedupe", options, map[string][]byte{"file": []byte(strings.Repeat("h", MaxHeader+1) + "\nx\n")}, "header_limit")
	assertCode(t, "dedupe", options, map[string][]byte{"file": make([]byte, MaxFile+1)}, "file_limit")
}

func TestGroupAndOutputByteLimitsAreAtomic(t *testing.T) {
	var data strings.Builder
	data.WriteString("id\n")
	for i := 0; i <= MaxGroups; i++ {
		fmt.Fprintf(&data, "%d\n", i)
	}
	assertCode(t, "aggregate", `{"group_columns":["id"],"metrics":[{"name":"n","op":"count_rows"}]}`, map[string][]byte{"file": []byte(data.String())}, "group_limit")
	// The input is below its cap, but JSON escaping exceeds the result cap.
	row := strings.Repeat("\t", 4000)
	data.Reset()
	data.WriteString("id\n")
	for i := 0; i < 1900; i++ {
		fmt.Fprintf(&data, "%d%s\n", i, row)
	}
	assertCode(t, "dedupe", `{"key_columns":["id"],"keep":"first"}`, map[string][]byte{"file": []byte(data.String())}, "output_byte_limit")
}

func TestFormulaStringsQuotedNewlinesAndCRLFRemainData(t *testing.T) {
	r := execute(t, "dedupe", `{"key_columns":["id"],"keep":"first"}`, map[string][]byte{"file": []byte("id,value\r\n01,\"=HYPERLINK(\"\"https://example.com\"\")\"\r\n02,\"line1\r\nline2\"\r\n")})
	if r.Rows[0][1] != `=HYPERLINK("https://example.com")` || r.Rows[1][1] != "line1\nline2" {
		t.Fatal(r.Rows)
	}
}

func FuzzDedupeNeverReturnsMalformedRows(f *testing.F) {
	f.Add([]byte("id,v\na,x\na,y\n"))
	f.Add([]byte("id\n"))
	f.Add([]byte("id\n\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFile {
			return
		}
		r, e := Execute("dedupe", json.RawMessage(`{"key_columns":["id"],"keep":"first"}`), map[string][]byte{"file": data})
		if e != nil {
			if r.Rows != nil {
				t.Fatal("partial result")
			}
			return
		}
		for _, row := range r.Rows {
			if len(row) != len(r.Columns) {
				t.Fatal("invalid shape")
			}
		}
	})
}
