// Package tabular implements small deterministic operations over string tables.
// It never opens files, accesses the network, evaluates expressions or logs data.
package tabular

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxFile    = 8 << 20
	MaxOptions = 32 << 10
	MaxRows    = 50_000
	MaxColumns = 128
	MaxHeader  = 256
	MaxCell    = 16 << 10
	MaxOutput  = 8 << 20
	MaxGroups  = 10_000
)

type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string  { return e.Code }
func bad(code string) error     { return &Error{code, 400} }
func limit(code string) error   { return &Error{code, 413} }
func invalid(code string) error { return &Error{code, 422} }

type Table struct {
	Columns []string
	Rows    [][]string
}
type Result struct {
	Operation  string         `json:"operation"`
	Columns    []string       `json:"columns"`
	Rows       [][]string     `json:"rows"`
	InputRows  map[string]int `json:"input_rows"`
	OutputRows int            `json:"output_rows"`
}

func ReadCSV(data []byte) (Table, error) {
	if len(data) > MaxFile {
		return Table{}, limit("file_limit")
	}
	if !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) || bytes.IndexByte(data, 0) >= 0 {
		return Table{}, bad("invalid_csv")
	}
	r := csv.NewReader(bytes.NewReader(data))
	header, err := r.Read()
	if err != nil {
		return Table{}, bad("invalid_csv")
	}
	if len(header) > MaxColumns {
		return Table{}, limit("column_limit")
	}
	seen := make(map[string]bool, len(header))
	for _, h := range header {
		if h == "" || seen[h] {
			return Table{}, invalid("invalid_header")
		}
		if len(h) > MaxHeader {
			return Table{}, limit("header_limit")
		}
		seen[h] = true
	}
	t := Table{Columns: header, Rows: make([][]string, 0)}
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Table{}, bad("invalid_csv")
		}
		if len(t.Rows) >= MaxRows {
			return Table{}, limit("row_limit")
		}
		for _, value := range row {
			if len(value) > MaxCell {
				return Table{}, limit("cell_limit")
			}
		}
		t.Rows = append(t.Rows, row)
	}
	return t, nil
}

// StrictJSON checks duplicate keys, nulls, exact field names and bounded depth
// before decoding. encoding/json alone accepts duplicate/case-folded field names.
func StrictJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > MaxOptions || !utf8.Valid(raw) || !validEscapedUnicode(raw) {
		return bad("invalid_options")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	count := 0
	var walk func(int) error
	walk = func(depth int) error {
		count++
		if depth > 8 || count > 1024 {
			return bad("invalid_options")
		}
		t, err := d.Token()
		if err != nil || t == nil {
			return bad("invalid_options")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return bad("invalid_options")
					}
					key, ok := k.(string)
					if !ok || len(key) > MaxHeader || seen[strings.ToLower(key)] {
						return bad("invalid_options")
					}
					seen[strings.ToLower(key)] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return bad("invalid_options")
				}
			case '[':
				for d.More() {
					if e := walk(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return bad("invalid_options")
				}
			default:
				return bad("invalid_options")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return bad("invalid_options")
	}
	if !exactFields(raw, reflect.TypeOf(dst).Elem()) {
		return bad("invalid_options")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return bad("invalid_options")
	}
	return nil
}

// JSON permits escaped UTF-16, but unpaired surrogates must not silently become
// replacement characters when selecting exact column names.
func validEscapedUnicode(raw []byte) bool {
	unit := func(at int) (uint64, bool) {
		if at+6 > len(raw) || raw[at] != '\\' || raw[at+1] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(string(raw[at+2:at+6]), 16, 16)
		return v, err == nil
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return false
		}
		if raw[i+1] != 'u' {
			i++
			continue
		}
		v, ok := unit(i)
		if !ok {
			return false
		}
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			low, ok := unit(i + 6)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
		i += 5
	}
	return true
}

func exactFields(raw []byte, t reflect.Type) bool {
	if t == reflect.TypeFor[json.RawMessage]() {
		return true
	} // Recursively checked by StrictJSON; schema checked by its consumer.
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return false
		}
		known := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			known[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		for name, value := range fields {
			ft, ok := known[name]
			if !ok || !exactFields(value, ft) {
				return false
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return false
		}
		for _, v := range values {
			if !exactFields(v, t.Elem()) {
				return false
			}
		}
	}
	return true
}

func columns(t Table, names []string, minCount, maxCount int) ([]int, error) {
	if len(names) < minCount || len(names) > maxCount {
		return nil, invalid("invalid_columns")
	}
	index := map[string]int{}
	for i, h := range t.Columns {
		index[h] = i
	}
	seen := map[string]bool{}
	result := make([]int, 0, len(names))
	for _, name := range names {
		i, ok := index[name]
		if !ok || seen[name] {
			return nil, invalid("invalid_columns")
		}
		seen[name] = true
		result = append(result, i)
	}
	return result, nil
}

// Length-prefixing prevents composite-key delimiter collisions.
func tuple(row []string, indices []int) string {
	var b strings.Builder
	for _, i := range indices {
		b.WriteString(strconv.Itoa(len(row[i])))
		b.WriteByte(':')
		b.WriteString(row[i])
	}
	return b.String()
}

type builder struct {
	result              Result
	baseBytes, rowBytes int
}

func newBuilder(op string, headers []string, inputs map[string]int) *builder {
	b := &builder{result: Result{Operation: op, Columns: headers, Rows: make([][]string, 0), InputRows: inputs}}
	base, _ := json.Marshal(b.result)
	b.baseBytes = len(base)
	return b
}
func (b *builder) add(row []string, maxRows int) error {
	if b.result.OutputRows >= maxRows {
		return limit("output_row_limit")
	}
	encoded, _ := json.Marshal(row)
	n := b.result.OutputRows + 1
	rowBytes := b.rowBytes + len(encoded)
	if n > 1 {
		rowBytes++
	}
	if b.baseBytes+rowBytes+len(strconv.Itoa(n))-1 > MaxOutput {
		return limit("output_byte_limit")
	}
	b.rowBytes = rowBytes
	b.result.OutputRows = n
	b.result.Rows = append(b.result.Rows, row)
	return nil
}

func Execute(operation string, raw json.RawMessage, inputs map[string][]byte) (Result, error) {
	if operation != "dedupe" && operation != "join" && operation != "aggregate" && operation != "transform" {
		return Result{}, bad("unknown_operation")
	}
	if len(raw) > MaxOptions {
		return Result{}, limit("options_limit")
	}
	expected := []string{"file"}
	if operation == "join" {
		expected = []string{"left", "right"}
	}
	if len(inputs) != len(expected) {
		return Result{}, bad("invalid_parts")
	}
	tables := map[string]Table{}
	for _, name := range expected {
		data, ok := inputs[name]
		if !ok {
			return Result{}, bad("invalid_parts")
		}
		t, err := ReadCSV(data)
		if err != nil {
			return Result{}, err
		}
		tables[name] = t
	}
	switch operation {
	case "dedupe":
		return dedupe(tables["file"], raw)
	case "join":
		return join(tables["left"], tables["right"], raw)
	case "transform":
		return transform(tables["file"], raw)
	default:
		return aggregate(tables["file"], raw)
	}
}
