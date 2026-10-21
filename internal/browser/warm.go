package browser

import (
	"context"
	"os"
	"sync"
)

// Warm owns a blank browser captured during image creation. Each cloned VM
// consumes its own copy exactly once. It never restarts or recycles a browser
// after receiving customer input. Only public synthetic checks run at build.
type Warm struct {
	Launcher, Executable string
	mu                   sync.Mutex
	session              *Session
	profile              string
	consumed             bool
}

func (w *Warm) Prepare(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.consumed {
		return ErrBrowser
	}
	if w.session != nil {
		return w.session.blank(ctx)
	}
	dir, err := os.MkdirTemp("", "utils-browser-base-")
	if err != nil {
		return ErrBrowser
	}
	s, err := StartPersistent(ctx, w.Launcher, w.Executable, dir)
	if err != nil {
		os.RemoveAll(dir)
		return err
	}
	// Remove initial about:blank targets. Customer renderers/contexts are created
	// only after restore, not inherited from the snapshot's default profile.
	if err = s.blank(ctx); err != nil {
		s.Close()
		os.RemoveAll(dir)
		return err
	}
	w.profile, w.session = dir, s
	return nil
}

func (s *Session) blank(ctx context.Context) error {
	var targets struct {
		Targets []struct {
			ID   string `json:"targetId"`
			URL  string `json:"url"`
			Type string `json:"type"`
		} `json:"targetInfos"`
	}
	if s.Call(ctx, "", "Target.getTargets", nil, &targets) != nil {
		return ErrBrowser
	}
	for _, target := range targets.Targets {
		if target.URL != "" && target.URL != "about:blank" {
			return ErrBrowser
		}
		if s.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": target.ID}, nil) != nil {
			return ErrBrowser
		}
	}
	return nil
}

// Restore verifies the snapshotted pipe and running process, without creating
// a renderer, navigating, generating customer IDs or starting another browser.
func (w *Warm) Restore(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.consumed || w.session == nil {
		return ErrBrowser
	}
	return w.session.blank(ctx)
}

func (w *Warm) Take(ctx context.Context) (*Session, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.consumed || w.session == nil {
		return nil, ErrBrowser
	}
	w.consumed = true
	if w.session.blank(ctx) != nil {
		w.session.Close()
		return nil, ErrBrowser
	}
	return w.session, nil
}

func (w *Warm) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.consumed = true
	if w.session != nil {
		w.session.Close()
	}
	if w.profile != "" {
		os.RemoveAll(w.profile)
	}
}

// Validate exercises the actual restored browser and pipe so AWS can observe
// the working set. The synthetic context is disposed before accepting work.
func (w *Warm) Validate(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.consumed || w.session == nil {
		return ErrBrowser
	}
	if CheckSession(ctx, w.session) != nil {
		return ErrBrowser
	}
	return w.session.blank(ctx)
}
