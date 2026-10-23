package csvwire

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"

	tabular "pdfservice/internal/csvtabular"
)

const StreamProtocol = "utilsbot-csv/2"
const MaxStreamBytes int64 = 1 << 30
const MaxStreamRows = 10_000_000

// Streaming v2 is a separate, transform-only profile. It never enters the v1
// whole-file engine. The only staging capability is a preopened private spool;
// no path, network or AWS capability is needed by the parser.
func ProcessStream(input io.Reader, output io.Writer, spool io.ReadWriteSeeker) error {
	var q Request
	if spool == nil || readFrame(input, &q) != nil || q.Version != 2 || q.Validate() != nil {
		return ErrWire
	}
	ih, oh, eh := sha256.New(), sha256.New(), sha256.New()
	encoded := &streamSink{w: io.MultiWriter(spool, eh), limit: MaxStreamBytes}
	z, _ := gzip.NewWriterLevel(encoded, gzip.BestSpeed)
	f := q.Files[0]
	stats, err := tabular.StreamTransform(io.TeeReader(io.LimitReader(input, f.Bytes), ih), io.MultiWriter(z, oh), q.Options, tabular.StreamLimits{InputBytes: f.Bytes, OutputBytes: MaxStreamBytes, Rows: MaxStreamRows})
	if err != nil || stats.InputBytes != f.Bytes || hex.EncodeToString(ih.Sum(nil)) != f.SHA256 {
		return ErrWorker
	}
	var tail [1]byte
	if n, e := input.Read(tail[:]); n != 0 || e != io.EOF {
		return ErrWire
	}
	if z.Close() != nil {
		return ErrWorker
	}
	m := Result{Version: 2, EncodedBytes: encoded.n, LogicalBytes: stats.OutputBytes, Rows: stats.Rows, EncodedSHA256: hex.EncodeToString(eh.Sum(nil)), LogicalSHA256: hex.EncodeToString(oh.Sum(nil))}
	if !m.Valid() {
		return ErrWorker
	}
	if _, e := spool.Seek(0, io.SeekStart); e != nil {
		return ErrWorker
	}
	if writeFrame(output, m) != nil {
		return ErrWire
	}
	if n, e := io.Copy(output, io.LimitReader(spool, m.EncodedBytes)); e != nil || n != m.EncodedBytes {
		return ErrWire
	}
	return nil
}

type streamSink struct {
	w        io.Writer
	n, limit int64
}

func (w *streamSink) Write(p []byte) (int, error) {
	if int64(len(p)) > w.limit-w.n {
		return 0, ErrWire
	}
	n, e := w.w.Write(p)
	w.n += int64(n)
	if n != len(p) && e == nil {
		e = io.ErrShortWrite
	}
	return n, e
}

// ReadStreamResult stages only declared bytes. Its caller owns the spool and
// must verify the decompressed CSV before any publication. Hash/length/trailing
// bytes are verified here without allocating a whole encoded file.
func ReadStreamResult(r io.Reader, w io.Writer) (Result, error) {
	var m Result
	if readFrame(r, &m) != nil || m.Version != 2 || !m.Valid() {
		return m, ErrWire
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(w, h), io.LimitReader(r, m.EncodedBytes))
	if e != nil || n != m.EncodedBytes || hex.EncodeToString(h.Sum(nil)) != m.EncodedSHA256 {
		return m, ErrWire
	}
	var tail [1]byte
	if n, e := r.Read(tail[:]); n != 0 || e != io.EOF {
		return m, ErrWire
	}
	return m, nil
}

func VerifyStreamResult(m Result, encoded io.ReadSeeker) error {
	if encoded == nil || m.Version != 2 || !m.Valid() {
		return ErrWire
	}
	if _, e := encoded.Seek(0, io.SeekStart); e != nil {
		return ErrWire
	}
	eh := sha256.New()
	limited := &io.LimitedReader{R: io.TeeReader(encoded, eh), N: m.EncodedBytes + 1}
	buffered := bufio.NewReaderSize(limited, 32<<10)
	z, e := gzip.NewReader(buffered)
	if e != nil {
		return ErrWire
	}
	z.Multistream(false)
	lh := sha256.New()
	logical := &streamCountReader{r: io.TeeReader(io.LimitReader(z, m.LogicalBytes+1), lh)}
	rows, e := tabular.ValidateStreamCSV(logical, m.LogicalBytes, MaxStreamRows)
	closeErr := z.Close()
	if e != nil || closeErr != nil || logical.n != m.LogicalBytes || rows != m.Rows || hex.EncodeToString(lh.Sum(nil)) != m.LogicalSHA256 {
		return ErrWire
	}
	// A second gzip member, padding, or bytes beyond the declared object fail.
	if _, e := buffered.ReadByte(); e != io.EOF {
		return ErrWire
	}
	if limited.N != 1 || hex.EncodeToString(eh.Sum(nil)) != m.EncodedSHA256 {
		return ErrWire
	}
	_, e = encoded.Seek(0, io.SeekStart)
	return e
}

type streamCountReader struct {
	r io.Reader
	n int64
}

func (r *streamCountReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	r.n += int64(n)
	return n, e
}
