package tabular

import "testing"

func TestStrictUnicodeColumnSelection(t *testing.T) {
	for _, raw := range []string{`{"key_columns":["\ud800"],"keep":"first"}`, `{"key_columns":["\udc00"],"keep":"first"}`, `{"key_columns":["\ud800\u0041"],"keep":"first"}`} {
		var opts DedupeOptions
		if StrictJSON([]byte(raw), &opts) == nil {
			t.Fatal("accepted unpaired UTF-16")
		}
	}
	for _, raw := range []string{`{"key_columns":["\ud83d\ude00"],"keep":"first"}`, `{"key_columns":["\\ud800"],"keep":"first"}`} {
		var opts DedupeOptions
		if err := StrictJSON([]byte(raw), &opts); err != nil {
			t.Fatal(err)
		}
	}
}
