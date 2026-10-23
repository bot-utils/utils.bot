package tabular

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// StreamLimits are independent of the small HTTP/JSON contract. Output is raw CSV.
type StreamLimits struct {
	InputBytes, OutputBytes int64
	Rows                    int
}
type StreamStats struct {
	InputBytes  int64 `json:"input_bytes"`
	OutputBytes int64 `json:"logical_bytes"`
	Rows        int   `json:"rows"`
}

// csvBoundedInput limits raw fields/records before encoding/csv can allocate them.
// Quote parity is used only for bounds; encoding/csv remains the strict parser.
type csvBoundedInput struct {
	source                io.Reader
	cap, total            int64
	field, record, fields int
	quoted                bool
	failure               error
}

func (r *csvBoundedInput) Read(p []byte) (int, error) {
	if r.failure != nil {
		return 0, r.failure
	}
	if int64(len(p)) > r.cap-r.total+1 {
		p = p[:r.cap-r.total+1]
	}
	n, err := r.source.Read(p)
	for i, b := range p[:n] {
		r.total++
		if r.total > r.cap {
			r.failure = limit("file_limit")
			return i, r.failure
		}
		r.field++
		r.record++
		if b == '"' {
			r.quoted = !r.quoted
		}
		if !r.quoted && b == '\n' {
			r.field = 0
			r.record = 0
			r.fields = 0
		} else if !r.quoted && b == ',' {
			r.field = 0
			r.fields++
		}
		if r.field > 2*MaxCell+4 {
			r.failure = limit("cell_limit")
			return i, r.failure
		}
		if r.record > MaxColumns*(2*MaxCell+4) {
			r.failure = limit("record_limit")
			return i, r.failure
		}
		if r.fields >= MaxColumns {
			r.failure = limit("column_limit")
			return i, r.failure
		}
	}
	if err != nil {
		r.failure = err
	}
	return n, err
}

type csvBoundedOutput struct {
	target     io.Writer
	cap, total int64
}

func (w *csvBoundedOutput) Write(p []byte) (int, error) {
	if int64(len(p)) > w.cap-w.total {
		return 0, limit("output_byte_limit")
	}
	n, err := w.target.Write(p)
	w.total += int64(n)
	if err != nil || n != len(p) {
		return n, &Error{Code: "output_unavailable", Status: 503}
	}
	return n, nil
}

func streamReadError(err error) error {
	var fixed *Error
	if errors.As(err, &fixed) {
		return fixed
	}
	return bad("invalid_csv")
}

func validCells(row []string) error {
	for _, v := range row {
		if !utf8.ValidString(v) || bytes.IndexByte([]byte(v), 0) >= 0 {
			return bad("invalid_csv")
		}
		if len(v) > MaxCell {
			return limit("cell_limit")
		}
	}
	return nil
}

// StreamTransform writes to private staging only. The caller must discard all
// bytes on error and publish only after Flush/encoder close and verification.
// No filesystem, network, credentials, logs or dynamic evaluation are used here.
func StreamTransform(input io.Reader, output io.Writer, raw json.RawMessage, limits StreamLimits) (StreamStats, error) {
	if limits.InputBytes <= 0 || limits.InputBytes > 1<<30 || limits.OutputBytes <= 0 || limits.OutputBytes > 2<<30 || limits.Rows <= 0 || limits.Rows > 10_000_000 {
		return StreamStats{}, bad("invalid_limits")
	}
	bounded := &csvBoundedInput{source: input, cap: limits.InputBytes}
	buffered := bufio.NewReaderSize(bounded, 32<<10)
	prefix, _ := buffered.Peek(3)
	if bytes.HasPrefix(prefix, []byte{0xef, 0xbb, 0xbf}) {
		return StreamStats{}, bad("invalid_csv")
	}
	reader := csv.NewReader(buffered)
	header, err := reader.Read()
	if err != nil {
		return StreamStats{}, streamReadError(err)
	}
	if len(header) > MaxColumns {
		return StreamStats{}, limit("column_limit")
	}
	seen := map[string]bool{}
	for _, h := range header {
		if !utf8.ValidString(h) || bytes.IndexByte([]byte(h), 0) >= 0 {
			return StreamStats{}, bad("invalid_csv")
		}
		if h == "" || seen[h] {
			return StreamStats{}, invalid("invalid_header")
		}
		if len(h) > MaxHeader {
			return StreamStats{}, limit("header_limit")
		}
		seen[h] = true
	}
	c, err := compileTransform(Table{Columns: header}, raw)
	if err != nil {
		return StreamStats{}, err
	}
	sink := &csvBoundedOutput{target: output, cap: limits.OutputBytes}
	writer := csv.NewWriter(sink)
	if err := writer.Write(header); err != nil {
		return StreamStats{}, streamReadError(err)
	}
	rows := 0
	for {
		row, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return StreamStats{}, streamReadError(e)
		}
		if rows >= limits.Rows {
			return StreamStats{}, limit("row_limit")
		}
		if e := validCells(row); e != nil {
			return StreamStats{}, e
		}
		row[c.column], e = c.apply(row[c.column])
		if e != nil {
			return StreamStats{}, e
		}
		if e := writer.Write(row); e != nil {
			return StreamStats{}, streamReadError(e)
		}
		rows++
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return StreamStats{}, streamReadError(err)
	}
	return StreamStats{InputBytes: bounded.total, OutputBytes: sink.total, Rows: rows}, nil
}

// ValidateStreamCSV applies the same bounded strict CSV/cell/header rules as
// the stream engine without retaining rows or performing a transformation.
func ValidateStreamCSV(input io.Reader, maxBytes int64, maxRows int) (int, error) {
	if maxBytes <= 0 || maxBytes > 1<<30 || maxRows < 0 || maxRows > 10_000_000 {
		return 0, bad("invalid_limits")
	}
	bounded := &csvBoundedInput{source: input, cap: maxBytes}
	buffered := bufio.NewReaderSize(bounded, 32<<10)
	prefix, _ := buffered.Peek(3)
	if bytes.HasPrefix(prefix, []byte{0xef, 0xbb, 0xbf}) {
		return 0, bad("invalid_csv")
	}
	reader := csv.NewReader(buffered)
	header, e := reader.Read()
	if e != nil {
		return 0, streamReadError(e)
	}
	if len(header) > MaxColumns {
		return 0, limit("column_limit")
	}
	seen := map[string]bool{}
	for _, h := range header {
		if h == "" || seen[h] || !utf8.ValidString(h) || bytes.IndexByte([]byte(h), 0) >= 0 {
			return 0, bad("invalid_header")
		}
		if len(h) > MaxHeader {
			return 0, limit("header_limit")
		}
		seen[h] = true
	}
	rows := 0
	for {
		row, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return 0, streamReadError(e)
		}
		if rows >= maxRows {
			return 0, limit("row_limit")
		}
		if e = validCells(row); e != nil {
			return 0, e
		}
		rows++
	}
	return rows, nil
}
