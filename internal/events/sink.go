package events

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Sink receives the encoded events, one JSON document per line
type Sink interface {
	// Write writes a batch of lines; a failed batch is retried at the next poll
	Write(lines [][]byte) error
	Name() string
}

// Writer writes to an io.Writer (stdout)
type Writer struct {
	mu   sync.Mutex
	W    io.Writer
	name string
}

// NewStdout writes the events to standard output
func NewStdout() *Writer {
	return &Writer{W: os.Stdout, name: "stdout"}
}

// NewWriter writes the events to w (tests)
func NewWriter(w io.Writer) *Writer {
	return &Writer{W: w, name: "writer"}
}

// Write implements Sink
func (s *Writer) Write(lines [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range lines {
		if _, err := s.W.Write(append(l, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// Name implements Sink
func (s *Writer) Name() string { return s.name }

// File appends the events to a file. The file is opened for every batch, so an
// external rotation (logrotate with create/rename) is picked up without signal.
type File struct {
	Path string
}

// Write implements Sink
func (f *File) Write(lines [][]byte) error {
	fh, err := os.OpenFile(f.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640) //nolint:gosec // operator-provided path
	if err != nil {
		return fmt.Errorf("open events file: %w", err)
	}
	for _, l := range lines {
		if _, err := fh.Write(append(l, '\n')); err != nil {
			_ = fh.Close()
			return fmt.Errorf("write events file: %w", err)
		}
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return fmt.Errorf("sync events file: %w", err)
	}
	return fh.Close()
}

// Name implements Sink
func (f *File) Name() string { return "file:" + f.Path }
