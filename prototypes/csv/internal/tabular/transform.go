package tabular

import (
	"encoding/json"
	"strings"
	"unicode"
)

// TransformUnicodeVersion pins casing and whitespace semantics across builds.
const TransformUnicodeVersion = "15.0.0"
const MaxReplacement = 1024

type TransformOptions struct {
	Column string  `json:"column"`
	Op     string  `json:"op"`
	Old    *string `json:"old"`
	New    *string `json:"new"`
}

// transform changes exactly one column, once, without evaluating cell contents.
// Every failure returns an empty Result, including a late expansion failure.
func transform(t Table, raw json.RawMessage) (Result, error) {
	var opts TransformOptions
	if err := StrictJSON(raw, &opts); err != nil {
		return Result{}, err
	}
	switch opts.Op {
	case "trim", "lower", "upper":
		if opts.Old != nil || opts.New != nil {
			return Result{}, bad("invalid_options")
		}
	case "replace":
		if opts.Old == nil || opts.New == nil || *opts.Old == "" ||
			len(*opts.Old) > MaxReplacement || len(*opts.New) > MaxReplacement ||
			strings.ContainsRune(*opts.Old, 0) || strings.ContainsRune(*opts.New, 0) {
			return Result{}, bad("invalid_options")
		}
	default:
		return Result{}, invalid("invalid_transform")
	}
	cols, err := columns(t, []string{opts.Column}, 1, 1)
	if err != nil {
		return Result{}, err
	}
	if unicode.Version != TransformUnicodeVersion {
		return Result{}, &Error{Code: "transform_unavailable", Status: 503}
	}
	column := cols[0]
	b := newBuilder("transform", append([]string{}, t.Columns...), map[string]int{"file": len(t.Rows)})
	for _, source := range t.Rows {
		value := source[column]
		switch opts.Op {
		case "trim":
			value = strings.TrimSpace(value)
		case "lower":
			value = strings.ToLower(value)
		case "upper":
			value = strings.ToUpper(value)
		case "replace":
			count := strings.Count(value, *opts.Old)
			// Reject expansion before allocating it; all lengths are UTF-8 bytes.
			if len(value)+count*(len(*opts.New)-len(*opts.Old)) > MaxCell {
				return Result{}, limit("cell_limit")
			}
			value = strings.ReplaceAll(value, *opts.Old, *opts.New)
		}
		if len(value) > MaxCell {
			return Result{}, limit("cell_limit")
		}
		row := append([]string{}, source...)
		row[column] = value
		if err := b.add(row, MaxRows); err != nil {
			return Result{}, err
		}
	}
	return b.result, nil
}
