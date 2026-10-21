package tabular

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

type DedupeOptions struct {
	KeyColumns []string `json:"key_columns"`
	Keep       string   `json:"keep"`
}

func dedupe(t Table, raw json.RawMessage) (Result, error) {
	var opts DedupeOptions
	if err := StrictJSON(raw, &opts); err != nil {
		return Result{}, err
	}
	if opts.Keep != "first" && opts.Keep != "last" {
		return Result{}, invalid("invalid_keep")
	}
	indices, err := columns(t, opts.KeyColumns, 1, 8)
	if err != nil {
		return Result{}, err
	}
	chosen := map[string]int{}
	for i, row := range t.Rows {
		key := tuple(row, indices)
		if _, exists := chosen[key]; !exists || opts.Keep == "last" {
			chosen[key] = i
		}
	}
	b := newBuilder("dedupe", t.Columns, map[string]int{"file": len(t.Rows)})
	for i, row := range t.Rows {
		if chosen[tuple(row, indices)] == i {
			if err := b.add(row, MaxRows); err != nil {
				return Result{}, err
			}
		}
	}
	return b.result, nil
}

type JoinOptions struct {
	LeftKeyColumns  []string `json:"left_key_columns"`
	RightKeyColumns []string `json:"right_key_columns"`
	Type            string   `json:"type"`
	RightPrefix     *string  `json:"right_prefix"`
}

func join(left, right Table, raw json.RawMessage) (Result, error) {
	var opts JoinOptions
	if err := StrictJSON(raw, &opts); err != nil {
		return Result{}, err
	}
	if opts.Type != "inner" && opts.Type != "left" && opts.Type != "semi" && opts.Type != "anti" {
		return Result{}, invalid("invalid_join_type")
	}
	li, err := columns(left, opts.LeftKeyColumns, 1, 8)
	if err != nil {
		return Result{}, err
	}
	ri, err := columns(right, opts.RightKeyColumns, 1, 8)
	if err != nil {
		return Result{}, err
	}
	if len(li) != len(ri) {
		return Result{}, invalid("invalid_columns")
	}
	prefix := "right_"
	if opts.RightPrefix != nil {
		prefix = *opts.RightPrefix
	}
	if len(prefix) > MaxHeader || !utf8.ValidString(prefix) {
		return Result{}, invalid("invalid_prefix")
	}
	headers := append([]string{}, left.Columns...)
	var extra []int
	if opts.Type == "inner" || opts.Type == "left" {
		keys := map[int]bool{}
		for _, i := range ri {
			keys[i] = true
		}
		leftNames := map[string]bool{}
		for _, h := range left.Columns {
			leftNames[h] = true
		}
		seen := map[string]bool{}
		for _, h := range headers {
			seen[h] = true
		}
		for i, h := range right.Columns {
			if keys[i] {
				continue
			}
			name := h
			if leftNames[h] {
				name = prefix + h
			}
			if seen[name] || len(name) > MaxHeader {
				return Result{}, invalid("output_column_collision")
			}
			seen[name] = true
			headers = append(headers, name)
			extra = append(extra, i)
		}
	}
	index := map[string][]int{}
	for i, row := range right.Rows {
		k := tuple(row, ri)
		index[k] = append(index[k], i)
	}
	b := newBuilder("join", headers, map[string]int{"left": len(left.Rows), "right": len(right.Rows)})
	pairs := 0
	for _, row := range left.Rows {
		matches := index[tuple(row, li)]
		if opts.Type == "semi" || opts.Type == "anti" {
			if (opts.Type == "semi" && len(matches) > 0) || (opts.Type == "anti" && len(matches) == 0) {
				if err := b.add(row, MaxRows); err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if len(matches) == 0 && opts.Type == "left" {
			joined := append([]string{}, row...)
			for range extra {
				joined = append(joined, "")
			}
			if err := b.add(joined, MaxRows); err != nil {
				return Result{}, err
			}
		}
		if len(matches) > MaxRows-pairs {
			return Result{}, limit("join_pair_limit")
		}
		pairs += len(matches)
		for _, i := range matches {
			joined := append([]string{}, row...)
			for _, j := range extra {
				joined = append(joined, right.Rows[i][j])
			}
			if err := b.add(joined, MaxRows); err != nil {
				return Result{}, err
			}
		}
	}
	return b.result, nil
}

type Metric struct {
	Name   string  `json:"name"`
	Op     string  `json:"op"`
	Column *string `json:"column"`
}
type AggregateOptions struct {
	GroupColumns []string `json:"group_columns"`
	Metrics      []Metric `json:"metrics"`
}
type accumulator struct {
	keys   []string
	count  int
	values []*big.Int
}

func aggregate(t Table, raw json.RawMessage) (Result, error) {
	var opts AggregateOptions
	if err := StrictJSON(raw, &opts); err != nil {
		return Result{}, err
	}
	groups, err := columns(t, opts.GroupColumns, 0, 4)
	if err != nil {
		return Result{}, err
	}
	if len(opts.Metrics) < 1 || len(opts.Metrics) > 8 {
		return Result{}, invalid("invalid_metrics")
	}
	headers := append([]string{}, opts.GroupColumns...)
	seen := map[string]bool{}
	for _, h := range headers {
		seen[h] = true
	}
	metricCols := make([]int, len(opts.Metrics))
	for i, m := range opts.Metrics {
		if m.Name == "" || len(m.Name) > MaxHeader || seen[m.Name] {
			return Result{}, invalid("invalid_metrics")
		}
		seen[m.Name] = true
		headers = append(headers, m.Name)
		if m.Op == "count_rows" {
			if m.Column != nil {
				return Result{}, invalid("invalid_metrics")
			}
			metricCols[i] = -1
			continue
		}
		if m.Op != "sum" && m.Op != "min" && m.Op != "max" || m.Column == nil {
			return Result{}, invalid("invalid_metrics")
		}
		cols, e := columns(t, []string{*m.Column}, 1, 1)
		if e != nil {
			return Result{}, e
		}
		metricCols[i] = cols[0]
	}
	var ordered []*accumulator
	index := map[string]*accumulator{}
	newGroup := func(row []string) *accumulator {
		a := &accumulator{keys: make([]string, 0, len(groups)), values: make([]*big.Int, len(opts.Metrics))}
		for _, j := range groups {
			a.keys = append(a.keys, row[j])
		}
		return a
	}
	if len(groups) == 0 {
		a := newGroup(nil)
		index[""] = a
		ordered = append(ordered, a)
	}
	for _, row := range t.Rows {
		key := tuple(row, groups)
		a := index[key]
		if a == nil {
			if len(ordered) >= MaxGroups {
				return Result{}, limit("group_limit")
			}
			a = newGroup(row)
			index[key] = a
			ordered = append(ordered, a)
		}
		a.count++
		for i, m := range opts.Metrics {
			if m.Op == "count_rows" {
				continue
			}
			value, e := decimal(row[metricCols[i]])
			if e != nil {
				return Result{}, e
			}
			if a.values[i] == nil {
				a.values[i] = value
				continue
			}
			switch m.Op {
			case "sum":
				a.values[i].Add(a.values[i], value)
			case "min":
				if value.Cmp(a.values[i]) < 0 {
					a.values[i] = value
				}
			case "max":
				if value.Cmp(a.values[i]) > 0 {
					a.values[i] = value
				}
			}
		}
	}
	b := newBuilder("aggregate", headers, map[string]int{"file": len(t.Rows)})
	for _, a := range ordered {
		row := append([]string{}, a.keys...)
		for i, m := range opts.Metrics {
			value := ""
			if m.Op == "count_rows" {
				value = strconv.Itoa(a.count)
			} else if a.values[i] != nil {
				value = canonical(a.values[i])
				digits := strings.TrimPrefix(strings.ReplaceAll(value, ".", ""), "-")
				if len(digits) > 43 {
					return Result{}, invalid("decimal_range")
				}
			} else if m.Op == "sum" {
				value = "0"
			}
			row = append(row, value)
		}
		if err := b.add(row, MaxGroups); err != nil {
			return Result{}, err
		}
	}
	return b.result, nil
}

// All decimal arithmetic uses signed integers scaled by 10^18. Inputs have
// at most 38 digits; at most 50,000 additions need at most five extra digits.
func decimal(s string) (*big.Int, error) {
	if s == "" {
		return nil, invalid("invalid_decimal")
	}
	negative := false
	if s[0] == '-' || s[0] == '+' {
		negative = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return nil, invalid("invalid_decimal")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 || parts[0] == "" {
		return nil, invalid("invalid_decimal")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if fraction == "" {
			return nil, invalid("invalid_decimal")
		}
	}
	if len(parts[0])+len(fraction) > 38 || len(fraction) > 18 {
		return nil, invalid("decimal_range")
	}
	for _, c := range parts[0] + fraction {
		if c < '0' || c > '9' {
			return nil, invalid("invalid_decimal")
		}
	}
	n, ok := new(big.Int).SetString(parts[0]+fraction+strings.Repeat("0", 18-len(fraction)), 10)
	if !ok {
		return nil, invalid("invalid_decimal")
	}
	if negative {
		n.Neg(n)
	}
	return n, nil
}
func canonical(n *big.Int) string {
	if n.Sign() == 0 {
		return "0"
	}
	abs := new(big.Int).Abs(n).String()
	if len(abs) <= 18 {
		abs = strings.Repeat("0", 19-len(abs)) + abs
	}
	whole, fraction := abs[:len(abs)-18], strings.TrimRight(abs[len(abs)-18:], "0")
	value := whole
	if fraction != "" {
		value += "." + fraction
	}
	if n.Sign() < 0 {
		value = "-" + value
	}
	return value
}
