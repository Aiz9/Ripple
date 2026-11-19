package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// StartLogCaptureAt preserves logs independently of PostgreSQL. Start capture
// before opening stores so startup failures survive until the next usable UI.
func StartLogCaptureAt(dataDir string) {
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			key := strings.ToUpper(parts[0])
			if strings.Contains(key, "API_KEY") || strings.Contains(key, "PASSWORD") || strings.Contains(key, "TOKEN") {
				RegisterLogSecret(parts[1])
			}
		}
	}
	StartLogCapture()
	if err := logSink.openJournal(filepath.Join(dataDir, "logs", "system.jsonl")); err != nil {
		log.Printf("[logs] ERROR cannot open durable log journal: %v", err)
	}
	logSink.importLauncherLogs(dataDir)
}

func (s *logSinkT) openJournal(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal != nil {
		file.Close()
		return nil
	}
	history, err := readJournalBefore(file, 0, s.cap)
	if err != nil {
		file.Close()
		return err
	}
	stat, _ := file.Stat()
	if stat.Size() > 0 {
		last := make([]byte, 1)
		_, _ = file.ReadAt(last, stat.Size()-1)
		if last[0] != '\n' {
			_, _ = file.Write([]byte("\n"))
		}
	}
	s.journal = file
	s.ring = history
	if len(history) > 0 {
		s.seq = history[len(history)-1].Seq
	}
	s.journalStartSeq = s.seq
	return nil
}

// Read backwards in bounded blocks rather than loading the whole journal. One
// record may contain multiple logical lines; JSON keeps it intact for display.
// A single JSON line may exceed the block size, so carry accumulates across
// blocks until a newline delimiter is found.
func readJournalBefore(file *os.File, before int64, limit int) ([]LogLine, error) {
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	offset := stat.Size()
	// carry holds the leftover prefix from the previous (more rightward) block
	// that hasn't been delimited by a newline yet. It can grow across multiple
	// blocks when a single JSON record is larger than the block size.
	carry := []byte{}
	lines := []LogLine{}
	consume := func(raw []byte) {
		var line LogLine
		if len(raw) > 0 && json.Unmarshal(raw, &line) == nil && (before <= 0 || line.Seq < before) {
			lines = append(lines, line)
		}
	}
	for offset > 0 && len(lines) < limit {
		size := int64(64 << 10)
		if offset < size {
			size = offset
		}
		offset -= size
		block := make([]byte, size)
		if _, err := file.ReadAt(block, offset); err != nil && err != io.EOF {
			return nil, err
		}
		// Prepend this block before carry so the full sequence is
		// [block bytes] + [carry from previous iterations].
		combined := append(block, carry...)
		end := len(combined)
		found := false
		for end > 0 && len(lines) < limit {
			index := bytes.LastIndexByte(combined[:end], '\n')
			if index < 0 {
				break
			}
			found = true
			consume(combined[index+1 : end])
			end = index
		}
		// Everything before the leftmost newline found (or the whole combined
		// buffer if no newline was found) becomes the carry for the next block.
		if found {
			carry = append([]byte{}, combined[:end]...)
		} else {
			carry = append([]byte{}, combined...)
		}
	}
	if offset == 0 && len(lines) < limit {
		consume(carry)
	}
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return lines, nil
}

func (s *logSinkT) journalHistory(before int64, limit int) ([]LogLine, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal == nil {
		return nil, false, nil
	}
	lines, err := readJournalBefore(s.journal, before, limit+1)
	more := len(lines) > limit
	if more {
		lines = lines[len(lines)-limit:]
	}
	return lines, more, err
}

// Launcher diagnostics are individual atomic spool files, so Python and Go do
// not contend for the journal's sequence or corrupt a shared JSONL append.
func (s *logSinkT) importLauncherLogs(dataDir string) {
	paths, _ := filepath.Glob(filepath.Join(dataDir, "logs", "pending", "*.json"))
	sort.Strings(paths)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var line LogLine
		if json.Unmarshal(raw, &line) != nil {
			continue
		}
		if line.Level == "" {
			line.Level = levelOf(line.Text)
		}
		if line.TS == "" {
			line.TS = time.Now().UTC().Format(time.RFC3339)
		}
		s.add(line)
		s.mu.Lock()
		durable := s.journal != nil && s.journalErr == nil
		s.mu.Unlock()
		if durable {
			_ = os.Remove(path)
		}
	}
}

func (s *logSinkT) closeJournal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal == nil {
		return nil
	}
	err := s.journal.Sync()
	closeErr := s.journal.Close()
	s.journal = nil
	if err != nil {
		return fmt.Errorf("flush log journal: %w", err)
	}
	return closeErr
}

func (s *logSinkT) after(since int64, limit int) ([]LogLine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ring) == 0 {
		return nil, nil
	}
	if s.journal == nil || since >= s.ring[0].Seq-1 {
		out := []LogLine{}
		for _, line := range s.ring {
			if line.Seq > since {
				out = append(out, line)
				if len(out) == limit {
					break
				}
			}
		}
		return out, nil
	}
	stat, err := s.journal.Stat()
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(io.NewSectionReader(s.journal, 0, stat.Size()))
	out := []LogLine{}
	for len(out) < limit {
		raw, err := reader.ReadBytes('\n')
		var line LogLine
		if json.Unmarshal(raw, &line) == nil && line.Seq > since {
			out = append(out, line)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Server) startLauncherLogImporter() {
	if s.ctx == nil || s.m == nil {
		return
	}
	s.controlledWG.Add(1)
	go func() {
		defer s.controlledWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				logSink.importLauncherLogs(s.m.dir)
			}
		}
	}()
}
