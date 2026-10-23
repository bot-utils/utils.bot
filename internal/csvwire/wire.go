// Package csvwire defines the private one-job CSV byte-stream protocol. It has
// no AWS, wallet, job-capability or network-client dependency.
package csvwire

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	tabular "pdfservice/internal/csvtabular"
	"pdfservice/internal/jsonwire"
)

var ErrWire = errors.New("csv_private_wire_invalid")
var ErrWorker = errors.New("csv_private_worker_failed")

const MaxHeader = 40 << 10
const MaxInput = tabular.MaxFile
const MaxOutput = tabular.MaxOutput
const Protocol = "utilsbot-csv/1"

type File struct {
	Slot   string `json:"slot"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Request struct {
	Version   int             `json:"version"`
	Operation string          `json:"operation"`
	Options   json.RawMessage `json:"options"`
	Files     []File          `json:"files"`
}
type Result struct {
	Version       int    `json:"version"`
	EncodedBytes  int64  `json:"encoded_bytes"`
	LogicalBytes  int64  `json:"logical_bytes"`
	Rows          int    `json:"rows"`
	EncodedSHA256 string `json:"encoded_sha256"`
	LogicalSHA256 string `json:"logical_sha256"`
}

func hash(p []byte) string { h := sha256.Sum256(p); return hex.EncodeToString(h[:]) }
func digest(s string) bool {
	v, e := hex.DecodeString(s)
	return e == nil && len(v) == 32 && hex.EncodeToString(v) == s
}
func (r Request) Validate() error {
	if (r.Version != 1 && r.Version != 2) || len(r.Files) < 1 || len(r.Files) > 2 {
		return ErrWire
	}
	if r.Version == 2 && r.Operation != "transform" {
		return ErrWire
	}
	canon, e := tabular.CanonicalOptions(r.Operation, r.Options)
	if e != nil || !bytes.Equal(canon, r.Options) {
		return ErrWire
	}
	if r.Operation == "join" {
		if len(r.Files) != 2 || r.Files[0].Slot != "left" || r.Files[1].Slot != "right" {
			return ErrWire
		}
	} else if len(r.Files) != 1 || r.Files[0].Slot != "file" {
		return ErrWire
	}
	cap := int64(MaxInput)
	if r.Version == 2 {
		cap = MaxStreamBytes
	}
	for _, f := range r.Files {
		if f.Bytes <= 0 || f.Bytes > cap || !digest(f.SHA256) {
			return ErrWire
		}
	}
	return nil
}
func writeFrame(w io.Writer, v any) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > MaxHeader {
		return ErrWire
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	if n, err := w.Write(size[:]); err != nil || n != len(size) {
		return ErrWire
	}
	if n, err := w.Write(raw); err != nil || n != len(raw) {
		return ErrWire
	}
	return nil
}
func readFrame(r io.Reader, v any) error {
	var size [4]byte
	if _, e := io.ReadFull(r, size[:]); e != nil {
		return ErrWire
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < 2 || n > MaxHeader {
		return ErrWire
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r, raw); e != nil {
		return ErrWire
	}
	if jsonwire.Decode(raw, v, MaxHeader) != nil {
		return ErrWire
	}
	canonical, _ := json.Marshal(v)
	if !bytes.Equal(canonical, raw) {
		return ErrWire
	}
	return nil
}

// WriteRequest streams exactly declared bytes and requires each source to end.
func WriteRequest(w io.Writer, q Request, inputs map[string]io.Reader) error {
	if q.Validate() != nil || len(inputs) != len(q.Files) {
		return ErrWire
	}
	if e := writeFrame(w, q); e != nil {
		return e
	}
	for _, f := range q.Files {
		r := inputs[f.Slot]
		if r == nil {
			return ErrWire
		}
		h := sha256.New()
		n, e := io.Copy(w, io.TeeReader(io.LimitReader(r, f.Bytes), h))
		if e != nil || n != f.Bytes || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
			return ErrWire
		}
		var extra [1]byte
		if n, e := r.Read(extra[:]); n != 0 || e != io.EOF {
			return ErrWire
		}
	}
	return nil
}
func readRequest(r io.Reader) (Request, map[string][]byte, error) {
	var q Request
	if readFrame(r, &q) != nil || q.Version != 1 || q.Validate() != nil {
		return q, nil, ErrWire
	}
	inputs := map[string][]byte{}
	for _, f := range q.Files {
		p := make([]byte, f.Bytes)
		if _, e := io.ReadFull(r, p); e != nil || hash(p) != f.SHA256 {
			return q, nil, ErrWire
		}
		inputs[f.Slot] = p
	}
	var tail [1]byte
	if n, e := r.Read(tail[:]); n != 0 || e != io.EOF {
		return q, nil, ErrWire
	}
	return q, inputs, nil
}

// Process may only run after the child/kernel sandbox is installed. No partial
// success frame is emitted: all parsing, output and gzip bounds are checked first.
func Process(r io.Reader, w io.Writer) error {
	q, in, e := readRequest(r)
	if e != nil {
		return e
	}
	result, e := tabular.Execute(q.Operation, q.Options, in)
	if e != nil {
		return ErrWorker
	}
	var plain bytes.Buffer
	out := csv.NewWriter(&plain)
	if e = out.Write(result.Columns); e != nil {
		return ErrWorker
	}
	for _, row := range result.Rows {
		if e = out.Write(row); e != nil || plain.Len() > MaxOutput {
			return ErrWorker
		}
	}
	out.Flush()
	if out.Error() != nil || plain.Len() > MaxOutput {
		return ErrWorker
	}
	var encoded bytes.Buffer
	z, _ := gzip.NewWriterLevel(&encoded, gzip.BestSpeed)
	if _, e = z.Write(plain.Bytes()); e != nil {
		return ErrWorker
	}
	if e = z.Close(); e != nil || encoded.Len() > MaxOutput {
		return ErrWorker
	}
	m := Result{Version: 1, EncodedBytes: int64(encoded.Len()), LogicalBytes: int64(plain.Len()), Rows: result.OutputRows, EncodedSHA256: hash(encoded.Bytes()), LogicalSHA256: hash(plain.Bytes())}
	if e = writeFrame(w, m); e != nil {
		return e
	}
	if n, err := w.Write(encoded.Bytes()); err != nil || n != encoded.Len() {
		return ErrWire
	}
	return nil
}
func (m Result) Valid() bool {
	cap, rows := int64(MaxOutput), tabular.MaxRows
	if m.Version == 2 {
		cap, rows = MaxStreamBytes, MaxStreamRows
	} else if m.Version != 1 {
		return false
	}
	return m.EncodedBytes > 0 && m.EncodedBytes <= cap && m.LogicalBytes > 0 && m.LogicalBytes <= cap && m.Rows >= 0 && m.Rows <= rows && digest(m.EncodedSHA256) && digest(m.LogicalSHA256)
}

// ReadResult verifies the complete wire and both hash domains before committing
// bytes to the broker's candidate sink. This private v1 is bounded to 8 MiB.
func ReadResult(r io.Reader, w io.Writer) (Result, error) {
	var m Result
	if readFrame(r, &m) != nil || m.Version != 1 || !m.Valid() {
		return m, ErrWire
	}
	data := make([]byte, m.EncodedBytes)
	if _, e := io.ReadFull(r, data); e != nil || hash(data) != m.EncodedSHA256 {
		return m, ErrWire
	}
	var tail [1]byte
	if n, e := r.Read(tail[:]); n != 0 || e != io.EOF {
		return m, ErrWire
	}
	if VerifyResult(m, data) != nil {
		return m, ErrWire
	}
	if n, err := w.Write(data); err != nil || n != len(data) {
		return m, ErrWire
	}
	return m, nil
}

func VerifyResult(m Result, data []byte) error {
	if m.Version != 1 || !m.Valid() || int64(len(data)) != m.EncodedBytes || hash(data) != m.EncodedSHA256 {
		return ErrWire
	}
	encoded := bytes.NewReader(data)
	z, e := gzip.NewReader(encoded)
	if e != nil {
		return ErrWire
	}
	z.Multistream(false)
	plain, e := io.ReadAll(io.LimitReader(z, m.LogicalBytes+1))
	ce := z.Close()
	if e != nil || ce != nil || int64(len(plain)) != m.LogicalBytes || hash(plain) != m.LogicalSHA256 || encoded.Len() != 0 {
		return ErrWire
	}
	table, e := tabular.ReadOutputCSV(plain)
	if e != nil || len(table.Rows) != m.Rows {
		return ErrWire
	}
	return nil
}
func (q Request) Binding() string {
	raw, _ := json.Marshal(q)
	return hash(append([]byte("csv-private-spec-v1|"), raw...))
}
func (Request) String() string   { return "CSV private request [redacted]" }
func (Request) GoString() string { return "CSV private request [redacted]" }
