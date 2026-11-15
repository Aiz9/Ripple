package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestShutdownWaitsForEvidenceAndArchives(t *testing.T) {
	s := &Server{}
	s.controlledWG.Add(1)
	s.archiveWG.Add(1)
	finished := make(chan error, 1)
	go func() { finished <- s.WaitForShutdown(t.Context()) }()
	s.controlledWG.Done()
	select {
	case <-finished:
		t.Fatal("shutdown closed before archive completion")
	case <-time.After(20 * time.Millisecond):
	}
	s.archiveWG.Done()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestShutdownDeadlineDoesNotHang(t *testing.T) {
	s := &Server{}
	s.controlledWG.Add(1)
	defer s.controlledWG.Done()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := s.WaitForShutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown deadline: %v", err)
	}
}
