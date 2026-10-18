package parser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"pdfservice/internal/jsonwire"
	"pdfservice/internal/protocol"
)

type Page struct {
	Index  int     `json:"index"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
	Text   string  `json:"text"`
	SHA256 string  `json:"sha256,omitempty"`
}
type Attempt struct {
	Engine  string `json:"engine"`
	Outcome string `json:"outcome"`
}
type Result struct {
	PageCount      int       `json:"pageCount"`
	Truncated      bool      `json:"truncated"`
	Pages          []Page    `json:"pages"`
	SelectedEngine string    `json:"selectedEngine"`
	Attempts       []Attempt `json:"attempts"`
	Warnings       []string  `json:"warnings,omitempty"`
}
type Parser struct {
	Dir     string
	Timeout time.Duration
}

var ErrDocument = errors.New("document_parse_failed")
var ErrSetup = errors.New("worker_setup_failed")

type limitedBuffer struct {
	b        bytes.Buffer
	cap      int
	exceeded bool
	cancel   context.CancelFunc
	mu       sync.Mutex
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remain := b.cap - b.b.Len()
	if remain > 0 {
		_, _ = b.b.Write(p[:min(n, remain)])
	}
	if n > remain {
		b.exceeded = true
		b.cancel()
		return n, nil
	}
	return n, nil
}
func (p Parser) Parse(ctx context.Context, data []byte) (Result, error) {
	var attempts []Attempt
	var empty *Result
	for _, engine := range []string{"pdfium", "poppler"} {
		result, outcome, err := p.attempt(ctx, engine, data)
		attempts = append(attempts, Attempt{Engine: engine, Outcome: outcome})
		if err == nil {
			result.SelectedEngine = engine
			hasText := false
			for _, page := range result.Pages {
				if strings.TrimSpace(page.Text) != "" {
					hasText = true
					break
				}
			}
			if hasText {
				result.Attempts = attempts
				return result, nil
			}
			if empty == nil {
				copy := result
				empty = &copy
			}
		}
		if errors.Is(err, ErrSetup) || ctx.Err() != nil {
			return Result{Attempts: attempts}, ErrSetup
		}
		if outcome == "password_required" {
			return Result{Attempts: attempts}, ErrDocument
		}
	}
	if empty != nil {
		empty.Attempts = attempts
		empty.Warnings = []string{"no_extractable_text"}
		return *empty, nil
	}
	return Result{Attempts: attempts}, ErrDocument
}
func (p Parser) attempt(ctx context.Context, engine string, data []byte) (Result, string, error) {
	// Never allow a missing or relative WORKER_DIR to turn this boundary into a
	// PATH lookup in the supervisor's environment. Production workers live in
	// the immutable image and are always addressed by an absolute path.
	if !filepath.IsAbs(p.Dir) {
		return Result{}, "setup_failed", ErrSetup
	}
	budget := p.Timeout
	if budget == 0 {
		budget = 10 * time.Second
	}
	childCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cmd := exec.CommandContext(childCtx, filepath.Join(p.Dir, engine+"-worker"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/nonexistent"}
	cmd.Stdin = bytes.NewReader(data)
	stdout := &limitedBuffer{cap: protocol.MaxOutput, cancel: cancel}
	stderr := &limitedBuffer{cap: 8 << 10, cancel: cancel}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Go's os.Process tracks the live child (pidfd on supported Linux); never kill a service group.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return Result{}, "setup_failed", ErrSetup
	}
	err := cmd.Wait() // Wait reaps this child before the fallback is started.
	if stdout.exceeded || stderr.exceeded {
		return Result{}, "output_limit", ErrDocument
	}
	if childCtx.Err() != nil {
		return Result{}, "timeout", ErrDocument
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if exit.ExitCode() == 20 {
				return Result{}, "setup_failed", ErrSetup
			}
			if exit.ExitCode() == 13 {
				return Result{}, "password_required", ErrDocument
			}
		}
		return Result{}, "document_error", ErrDocument
	}
	result, err := decodeResult(stdout.b.Bytes())
	if err != nil {
		return Result{}, "invalid_output", ErrDocument
	}
	if err = validate(&result); err != nil {
		return Result{}, "invalid_output", ErrDocument
	}
	outcome := "success"
	if len(result.Pages) == 0 {
		outcome = "no_text"
	}
	return result, outcome, nil
}

// Decode pages incrementally so an untrusted array cannot allocate thousands of
// page structs before the count limit is checked.
func decodeResult(raw []byte) (Result, error) {
	var result Result
	if err := jsonwire.Check(raw, protocol.MaxOutput); err != nil {
		return result, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return result, errors.New("invalid result object")
	}
	seen := make(map[string]bool, 3)
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return result, err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return result, errors.New("invalid or duplicate result field")
		}
		seen[key] = true
		switch key {
		case "pageCount":
			var count *int
			err = dec.Decode(&count)
			if err == nil && count == nil {
				return result, errors.New("missing page count")
			}
			if err == nil {
				result.PageCount = *count
			}
		case "truncated":
			var truncated *bool
			err = dec.Decode(&truncated)
			if err == nil && truncated == nil {
				return result, errors.New("missing truncation flag")
			}
			if err == nil {
				result.Truncated = *truncated
			}
		case "pages":
			token, err = dec.Token()
			if err != nil || token != json.Delim('[') {
				return result, errors.New("invalid pages array")
			}
			total := 0
			for dec.More() {
				if len(result.Pages) >= protocol.MaxPages {
					return result, errors.New("page count limit")
				}
				var wire struct {
					Index  *int     `json:"index"`
					Width  *float64 `json:"width"`
					Height *float64 `json:"height"`
					Text   *string  `json:"text"`
				}
				if err = dec.Decode(&wire); err != nil {
					return result, err
				}
				if wire.Index == nil || wire.Width == nil || wire.Height == nil || wire.Text == nil {
					return result, errors.New("incomplete page")
				}
				page := Page{Index: *wire.Index, Width: *wire.Width, Height: *wire.Height, Text: *wire.Text}
				total += len(page.Text)
				if total > protocol.MaxText {
					return result, errors.New("text limit")
				}
				result.Pages = append(result.Pages, page)
			}
			token, err = dec.Token()
			if err == nil && token != json.Delim(']') {
				err = errors.New("invalid pages end")
			}
		default:
			return result, errors.New("unknown result field")
		}
		if err != nil {
			return result, err
		}
	}
	token, err = dec.Token()
	if err != nil || token != json.Delim('}') || len(seen) != 3 {
		return result, errors.New("incomplete result")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return result, errors.New("trailing result data")
	}
	return result, nil
}

func validate(r *Result) error {
	if r.PageCount < 0 || r.PageCount > 10_000_000 || len(r.Pages) > protocol.MaxPages || len(r.Pages) > r.PageCount || (len(r.Pages) < r.PageCount && !r.Truncated) {
		return fmt.Errorf("invalid pages")
	}
	total := 0
	for i := range r.Pages {
		p := &r.Pages[i]
		if p.Index != i || math.IsNaN(p.Width) || math.IsNaN(p.Height) || math.IsInf(p.Width, 0) || math.IsInf(p.Height, 0) || p.Width < 0 || p.Height < 0 || p.Width > 1e9 || p.Height > 1e9 || !utf8.ValidString(p.Text) {
			return fmt.Errorf("invalid page")
		}
		total += len(p.Text)
		if total > protocol.MaxText {
			return fmt.Errorf("text limit")
		}
		p.SHA256 = protocol.SHA256([]byte(p.Text))
	}
	return nil
}
