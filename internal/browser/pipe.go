// Package browser controls one sandboxed Chromium process over private pipes.
// It has no WebSocket listener, cross-customer reuse, or caller-controlled flags.
package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

var ErrBrowser = errors.New("browser_unavailable")

// This must match the verified official artifact in Dockerfile.browser.
const Version = "156.0.8078.47"

const maxMessage = 32 << 20

type message struct {
	ID      int             `json:"id,omitempty"`
	Session string          `json:"sessionId,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}
type Session struct {
	cmd           *exec.Cmd
	input, output *os.File
	events        chan message
	done          chan struct{}
	mu            sync.Mutex
	next          int
	pending       map[int]chan message
	write         sync.Mutex
	once          sync.Once
}

// Start requires the network-denying launcher and Chromium's namespace sandbox.
// An unavailable sandbox is an error, never a reason to use --no-sandbox.
func Start(ctx context.Context, launcher, executable, profile string) (*Session, error) {
	return start(ctx, ctx, launcher, executable, profile)
}

// StartPersistent initializes a customer-free browser for the image snapshot.
// Its lifetime must not inherit a build hook deadline that expires after thaw.
// The caller must Close it after its sole job or on initialization failure.
func StartPersistent(ctx context.Context, launcher, executable, profile string) (*Session, error) {
	return start(ctx, context.Background(), launcher, executable, profile)
}

func start(ctx, lifetime context.Context, launcher, executable, profile string) (*Session, error) {
	if protectParent() != nil {
		return nil, ErrBrowser
	}
	if launcher == "" || executable == "" || profile == "" {
		return nil, ErrBrowser
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, ErrBrowser
	}
	output, browserOutput, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, ErrBrowser
	}
	cmd := exec.Command(launcher, executable,
		"--remote-debugging-pipe", "--disable-setuid-sandbox", "--disable-gpu", "--disable-software-rasterizer", "--disable-webgl", "--disable-webgl2",
		"--disable-dev-shm-usage", "--disable-background-networking", "--disable-component-update",
		"--disable-default-apps", "--disable-extensions", "--disable-sync", "--no-first-run",
		"--no-default-browser-check", "--disable-breakpad", "--disable-crash-reporter",
		"--disable-quic", "--mute-audio", "--disable-features=MediaRouter,OptimizationHints,Translate",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--js-flags=--max-old-space-size=128",
		"--user-data-dir="+profile, "about:blank")
	cmd.Env = []string{"HOME=" + profile, "TMPDIR=" + profile, "LANG=C.UTF-8", "PATH=/usr/bin:/bin", "GLIBC_TUNABLES=glibc.pthread.stack_cache_size=0"}
	cmd.ExtraFiles = []*os.File{reader, browserOutput}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		reader.Close()
		writer.Close()
		output.Close()
		browserOutput.Close()
		return nil, ErrBrowser
	}
	reader.Close()
	browserOutput.Close()
	s := &Session{cmd: cmd, input: writer, output: output, events: make(chan message, 128), done: make(chan struct{}), pending: make(map[int]chan message)}
	go s.read()
	go func() {
		select {
		case <-lifetime.Done():
			s.Close()
		case <-s.done:
		}
	}()
	var version struct {
		Product string `json:"product"`
	}
	if err := s.Call(ctx, "", "Browser.getVersion", nil, &version); err != nil || version.Product != "HeadlessChrome/"+Version {
		s.Close()
		return nil, ErrBrowser
	}
	return s, nil
}
func (s *Session) Close() {
	s.once.Do(func() {
		syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		s.input.Close()
		s.output.Close()
		s.cmd.Wait()
		close(s.done)
	})
}
func (s *Session) read() {
	r := bufio.NewReaderSize(s.output, 64<<10)
	for {
		var wire []byte
		for {
			chunk, err := r.ReadSlice(0)
			if len(wire)+len(chunk) > maxMessage {
				go s.Close()
				return
			}
			wire = append(wire, chunk...)
			if err == nil {
				break
			}
			if err != bufio.ErrBufferFull {
				go s.Close()
				return
			}
		}
		var m message
		if len(wire) < 2 || json.Unmarshal(wire[:len(wire)-1], &m) != nil {
			go s.Close()
			return
		}
		if m.ID == 0 && len(wire) > 64<<10 {
			go s.Close()
			return
		}
		if m.ID != 0 {
			s.mu.Lock()
			ch := s.pending[m.ID]
			s.mu.Unlock()
			if ch != nil {
				select {
				case ch <- m:
				default:
				}
			}
		} else {
			select {
			case s.events <- m:
			case <-s.done:
				return
			default:
				go s.Close()
				return
			}
		}
	}
}
func (s *Session) Call(ctx context.Context, session, method string, params any, out any) error {
	p, err := json.Marshal(params)
	if err != nil {
		return ErrBrowser
	}
	ch := make(chan message, 1)
	s.mu.Lock()
	s.next++
	id := s.next
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, id); s.mu.Unlock() }()
	wire, err := json.Marshal(message{ID: id, Session: session, Method: method, Params: p})
	if err != nil {
		return ErrBrowser
	}
	wire = append(wire, 0)
	s.write.Lock()
	_, err = s.input.Write(wire)
	s.write.Unlock()
	if err != nil {
		return ErrBrowser
	}
	select {
	case m := <-ch:
		if len(m.Error) > 0 {
			return ErrBrowser
		}
		if out != nil && json.Unmarshal(m.Result, out) != nil {
			return ErrBrowser
		}
		return nil
	case <-ctx.Done():
		return ErrBrowser
	case <-s.done:
		return ErrBrowser
	}
}
