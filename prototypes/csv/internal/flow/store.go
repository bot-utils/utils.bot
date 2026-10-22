// Package flow implements a private, synthetic-only local protocol rehearsal.
// Its bounded local snapshot is not a production storage or AWS adapter.
package flow

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const snapshotLimit = 46 << 20
const aggregateLimit = 96 << 20

type Store struct {
	mu     sync.Mutex
	root   string
	lock   *os.File
	closed bool
}

func privateFile(path string, flags int) (*os.File, error) {
	f, e := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("unsafe_state_file")
	}
	if stat, ok := s.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("unsafe_state_owner")
	}
	return f, nil
}

// OpenStore requires an existing private directory. One process owns it until Close.
func OpenStore(root string) (*Store, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("absolute_private_state_required")
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil || real != filepath.Clean(root) {
		return nil, errors.New("unsafe_state_directory")
	}
	s, e := os.Lstat(root)
	if e != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return nil, errors.New("private_state_directory_required")
	}
	stat, ok := s.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("unsafe_state_owner")
	}
	lock, e := privateFile(filepath.Join(root, "control.lock"), os.O_CREATE|os.O_RDWR)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("state_already_owned")
	}
	store := &Store{root: root, lock: lock}
	if e = store.tx(true, func(d *database) error {
		if d.Schema == 0 {
			d.Schema = 1
			d.Key = random()
			d.Jobs = map[string]*job{}
			d.Idempotency = map[string]string{}
			d.Nonces = map[string]string{}
			d.Provider = map[string]string{}
		}
		if d.Schema != 1 {
			return errors.New("unknown_state_schema")
		}
		return nil
	}); e != nil {
		store.Close()
		return nil, e
	}
	return store, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.lock.Close()
}
func (s *Store) tx(write bool, fn func(*database) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("state_closed")
	}
	d := &database{}
	f, e := privateFile(filepath.Join(s.root, "control.json"), os.O_RDONLY)
	if e == nil {
		raw, err := io.ReadAll(io.LimitReader(f, snapshotLimit+1))
		f.Close()
		if err != nil || len(raw) > snapshotLimit || json.Unmarshal(raw, d) != nil {
			return errors.New("state_unavailable")
		}
		if d.Schema != 1 || !secret(d.Key) || d.Jobs == nil || d.Idempotency == nil || d.Nonces == nil || d.Provider == nil {
			return errors.New("invalid_state_schema")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	callErr := fn(d)
	var known *Error
	if !write || callErr != nil && !errors.As(callErr, &known) {
		return callErr
	}
	raw, e := json.Marshal(d)
	if e != nil || len(raw) > snapshotLimit {
		return errors.New("state_limit")
	}
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return e
	}
	var current int64
	for _, entry := range entries {
		if entry.Name() != "control.json" && entry.Name() != "control.next" && entry.Name() != "control.lock" {
			return errors.New("unexpected_state_file")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > snapshotLimit {
			return errors.New("unsafe_state_file")
		}
		if entry.Name() != "control.next" {
			current += info.Size()
		}
	}
	if current+int64(len(raw)) > aggregateLimit {
		return errors.New("aggregate_state_limit")
	}
	next, e := privateFile(filepath.Join(s.root, "control.next"), os.O_CREATE|os.O_WRONLY)
	if e != nil {
		return e
	}
	// Only mutate after validating an existing file's ownership, type and permissions.
	if e = next.Truncate(0); e == nil {
		_, e = next.Write(raw)
	}
	if e == nil {
		e = next.Sync()
	}
	closeErr := next.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(filepath.Join(s.root, "control.next"), filepath.Join(s.root, "control.json")); e != nil {
		return e
	}
	dir, e := os.Open(s.root)
	if e != nil {
		return e
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		return e
	}
	return callErr
}
