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

// compiledTransform is shared by request-sized and streaming execution.
type compiledTransform struct {
	options TransformOptions
	column  int
}

func compileTransform(t Table, raw json.RawMessage) (compiledTransform, error) {
	var opts TransformOptions
	if err := StrictJSON(raw, &opts); err != nil {
		return compiledTransform{}, err
	}
	switch opts.Op {
	case "trim", "lower", "upper":
		if opts.Old != nil || opts.New != nil {
			return compiledTransform{}, bad("invalid_options")
		}
	case "replace":
		if opts.Old == nil || opts.New == nil || *opts.Old == "" || len(*opts.Old) > MaxReplacement || len(*opts.New) > MaxReplacement || strings.ContainsRune(*opts.Old, 0) || strings.ContainsRune(*opts.New, 0) {
			return compiledTransform{}, bad("invalid_options")
		}
	default:
		return compiledTransform{}, invalid("invalid_transform")
	}
	cols, err := columns(t, []string{opts.Column}, 1, 1)
	if err != nil {
		return compiledTransform{}, err
	}
	if unicode.Version != TransformUnicodeVersion {
		return compiledTransform{}, &Error{Code: "transform_unavailable", Status: 503}
	}
	return compiledTransform{opts, cols[0]}, nil
}

func (c compiledTransform) apply(value string) (string, error) {
	opts := c.options
	switch opts.Op {
	case "trim":
		value = strings.TrimSpace(value)
	case "lower":
		value = strings.ToLower(value)
	case "upper":
		value = strings.ToUpper(value)
	case "replace":
		count := strings.Count(value, *opts.Old)
		if len(value)+count*(len(*opts.New)-len(*opts.Old)) > MaxCell {
			return "", limit("cell_limit")
		}
		value = strings.ReplaceAll(value, *opts.Old, *opts.New)
	}
	if len(value) > MaxCell {
		return "", limit("cell_limit")
	}
	return value, nil
}

// transform changes exactly one column. Failures never return partial rows.
func transform(t Table, raw json.RawMessage) (Result, error) {
	c, err := compileTransform(t, raw)
	if err != nil {
		return Result{}, err
	}
	b := newBuilder("transform", append([]string{}, t.Columns...), map[string]int{"file": len(t.Rows)})
	for _, source := range t.Rows {
		value, err := c.apply(source[c.column])
		if err != nil {
			return Result{}, err
		}
		row := append([]string{}, source...)
		row[c.column] = value
		if err := b.add(row, MaxRows); err != nil {
			return Result{}, err
		}
	}
	return b.result, nil
}
