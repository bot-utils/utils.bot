package tabular

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
)

// CanonicalOptions validates options before storage admission without customer
// data. Header-dependent conflicts are still checked against the actual upload.
func CanonicalOptions(op string, raw json.RawMessage) (json.RawMessage, error) {
	var normalized any
	headers := map[string][]string{}
	add := func(slot string, names ...string) {
		for _, n := range names {
			found := false
			for _, v := range headers[slot] {
				if n == v {
					found = true
				}
			}
			if !found {
				headers[slot] = append(headers[slot], n)
			}
		}
	}
	switch op {
	case "dedupe":
		var o DedupeOptions
		if e := StrictJSON(raw, &o); e != nil {
			return nil, e
		}
		add("file", o.KeyColumns...)
		normalized = o
	case "join":
		var o JoinOptions
		if e := StrictJSON(raw, &o); e != nil {
			return nil, e
		}
		if o.RightPrefix == nil {
			v := "right_"
			o.RightPrefix = &v
		}
		add("left", o.LeftKeyColumns...)
		add("right", o.RightKeyColumns...)
		normalized = o
	case "aggregate":
		var o AggregateOptions
		if e := StrictJSON(raw, &o); e != nil {
			return nil, e
		}
		if o.GroupColumns == nil {
			o.GroupColumns = []string{}
		}
		add("file", o.GroupColumns...)
		metrics := make([]map[string]any, 0, len(o.Metrics))
		for _, m := range o.Metrics {
			v := map[string]any{"name": m.Name, "op": m.Op}
			if m.Column != nil {
				add("file", *m.Column)
				v["column"] = *m.Column
			}
			metrics = append(metrics, v)
		}
		normalized = map[string]any{"group_columns": o.GroupColumns, "metrics": metrics}
	case "transform":
		var o TransformOptions
		if e := StrictJSON(raw, &o); e != nil {
			return nil, e
		}
		add("file", o.Column)
		v := map[string]any{"column": o.Column, "op": o.Op}
		if o.Old != nil {
			v["old"] = *o.Old
		}
		if o.New != nil {
			v["new"] = *o.New
		}
		normalized = v
	default:
		return nil, bad("unknown_operation")
	}
	if len(headers) == 0 {
		headers["file"] = []string{"_reference"}
	}
	inputs := map[string][]byte{}
	for slot, names := range headers {
		if len(names) == 0 {
			names = []string{"_reference"}
		}
		var b bytes.Buffer
		w := csv.NewWriter(&b)
		if e := w.Write(names); e != nil {
			return nil, e
		}
		w.Flush()
		inputs[slot] = b.Bytes()
	}
	canon, e := json.Marshal(normalized)
	if e != nil {
		return nil, bad("invalid_options")
	}
	if _, e = Execute(op, canon, inputs); e != nil {
		return nil, e
	}
	return canon, nil
}
