// Package state persists the position of the event stream between restarts:
// the cursor (date of the newest exported event) and the identifiers of the
// events already exported inside the late-arrival window, so that re-reading
// the window after a restart never emits an event twice.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the persisted position of the event stream
type State struct {
	// Cursor is the date of the newest exported event
	Cursor time.Time `json:"cursor"`
	// Seen maps the exported event ids of the late-arrival window to their
	// date in Unix microseconds
	Seen map[string]int64 `json:"seen"`
}

// New returns an empty state starting at cursor
func New(cursor time.Time) *State {
	return &State{Cursor: cursor.UTC(), Seen: map[string]int64{}}
}

// MarkSeen records an exported event
func (s *State) MarkSeen(id string, date time.Time) {
	s.Seen[id] = date.UnixMicro()
}

// IsSeen reports whether an event was already exported
func (s *State) IsSeen(id string) bool {
	_, ok := s.Seen[id]
	return ok
}

// Prune forgets the events older than before: they are outside the window
// and will not be read again
func (s *State) Prune(before time.Time) {
	limit := before.UnixMicro()
	for id, ts := range s.Seen {
		if ts < limit {
			delete(s.Seen, id)
		}
	}
}

// Clone returns a deep copy
func (s *State) Clone() *State {
	out := &State{Cursor: s.Cursor, Seen: make(map[string]int64, len(s.Seen))}
	for k, v := range s.Seen {
		out.Seen[k] = v
	}
	return out
}

// Marshal encodes the state as compact JSON
func (s *State) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// Unmarshal decodes a state
func Unmarshal(data []byte) (*State, error) {
	s := &State{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("invalid state: %w", err)
	}
	if s.Seen == nil {
		s.Seen = map[string]int64{}
	}
	s.Cursor = s.Cursor.UTC()
	return s, nil
}

// Store loads and saves the state
type Store interface {
	// Load returns the saved state, or found=false when nothing was saved yet
	Load(ctx context.Context) (st *State, found bool, err error)
	// Save persists the state
	Save(ctx context.Context, st *State) error
	// Name describes the backend for the logs
	Name() string
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

// Memory keeps the state in memory only (lost on restart)
type Memory struct {
	mu sync.Mutex
	st *State
}

// Load implements Store
func (m *Memory) Load(context.Context) (*State, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return nil, false, nil
	}
	return m.st.Clone(), true, nil
}

// Save implements Store
func (m *Memory) Save(_ context.Context, st *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st = st.Clone()
	return nil
}

// Name implements Store
func (m *Memory) Name() string { return "memory" }

// ---------------------------------------------------------------------------
// File
// ---------------------------------------------------------------------------

// File stores the state in a JSON file, replaced atomically
type File struct {
	Path string
}

// Load implements Store
func (f *File) Load(context.Context) (*State, bool, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read state file: %w", err)
	}
	st, err := Unmarshal(data)
	if err != nil {
		return nil, false, err
	}
	return st, true, nil
}

// Save implements Store: write to a temporary file then rename, so that a
// crash never leaves a truncated state
func (f *File) Save(_ context.Context, st *State) error {
	data, err := st.Marshal()
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state file: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}

// Name implements Store
func (f *File) Name() string { return "file:" + f.Path }
