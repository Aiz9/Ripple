package server

import "context"

// WaitForShutdown lets cancelled jobs save their final evidence before the
// database is closed. The caller must cancel the server context first.
func (s *Server) WaitForShutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.controlledWG.Wait()
		s.archiveWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
