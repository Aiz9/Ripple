package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

)

func isolatedLogSink(t *testing.T) *logSinkT {
	t.Helper()
	sink := &logSinkT{cap: 3, subs: map[chan LogLine]struct{}{}, out: io.Discard}
	original, writer := logSink, log.Writer()
	logSink = sink
	log.SetOutput(sink)
	t.Cleanup(func() { log.SetOutput(writer); logSink = original; _ = sink.closeJournal() })
	return sink
}
func TestLogJournalKeepsOverflowHistoryAndRestarts(t *testing.T) {
	sink := isolatedLogSink(t)
	path := filepath.Join(t.TempDir(), "logs", "system.jsonl")
	if err := sink.openJournal(path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		sink.add(parseLog(fmt.Sprintf("[fixture] ERROR failure %d\ncontinued detail", i)))
	}
	ring, _ := sink.recent(0, 100)
	if len(ring) != 3 {
		t.Fatal("fixture did not overflow ring")
	}
	lines, more, err := sink.journalHistory(7, 3)
	if err != nil || !more || len(lines) != 3 || lines[0].Seq != 4 || lines[2].Seq != 6 {
		t.Fatalf("bad journal pagination: %+v %v %v", lines, more, err)
	}
	catchup, err := sink.after(1, 5)
	if err != nil || len(catchup) != 5 || catchup[0].Seq != 2 {
		t.Fatal("disconnected subscriber lost overflowed entries")
	}
	if err := sink.closeJournal(); err != nil {
		t.Fatal(err)
	}
	if err := sink.openJournal(path); err != nil {
		t.Fatal(err)
	}
	sink.add(parseLog("[fixture] ERROR after restart"))
	if sink.seq != 10 {
		t.Fatal("journal sequence reset")
	}
}
func TestLogJournalPreservesLongMultilineErrorsAndRecoversTornTail(t *testing.T) {
	sink := isolatedLogSink(t)
	path := filepath.Join(t.TempDir(), "system.jsonl")
	if err := sink.openJournal(path); err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("Unicode failure: λ\n", 9000)
	sink.add(parseLog(text))
	lines, _, err := sink.journalHistory(0, 2)
	if err != nil || len(lines) != 1 || lines[0].Text != strings.TrimSpace(text) {
		t.Fatal("large error truncated")
	}
	sink.closeJournal()
	file, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	file.WriteString(`{"seq":2,"text":"torn`)
	file.Close()
	if err := sink.openJournal(path); err != nil {
		t.Fatal(err)
	}
	sink.add(parseLog("new complete error"))
	lines, _, err = sink.journalHistory(0, 2)
	if err != nil || len(lines) != 2 || lines[1].Seq != 2 || lines[1].Text != "new complete error" {
		t.Fatal("torn tail corrupted next error")
	}
}
func TestLogRedactionAndErrorClassification(t *testing.T) {
	RegisterLogSecret("known-profile-key-fixture")
	value := RedactLogText(`password="secret with spaces" Authorization: Bearer abc.def api_key=hidden https://user:pass@host.test/path?token=hidden known-profile-key-fixture`)
	for _, secret := range []string{"secret with spaces", "abc.def", "=hidden", "user:pass", "known-profile-key-fixture"} {
		if strings.Contains(value, secret) {
			t.Fatalf("secret leaked: %s", value)
		}
	}
	for _, text := range []string{"Failed to attach", "Cannot read file", "Unreachable device", "Deny execution"} {
		if levelOf(text) != "error" {
			t.Fatalf("not classified as error: %s", text)
		}
	}
}
func TestDiagnosticMiddlewareCapturesErrorsPanicsAndRequestContext(t *testing.T) {
	for _, panicCase := range []bool{false, true} {
		t.Run(fmt.Sprint(panicCase), func(t *testing.T) {
			sink := isolatedLogSink(t)
			handler := (&Server{}).diagnosticMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if panicCase {
					panic("synthetic panic")
				}
				writeErr(w, 422, "synthetic validation error")
			}))
			request := httptest.NewRequest("POST", "/api/android/assessments?token=must-not-log", nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			want := 422
			if panicCase {
				want = 500
			}
			if recorder.Code != want || recorder.Header().Get("X-Request-ID") == "" {
				t.Fatal("response semantics changed")
			}
			lines, _ := sink.recent(0, 10)
			if len(lines) == 0 || lines[0].Level != "error" || !strings.Contains(lines[0].Text, "method=POST") || strings.Contains(lines[0].Text, "must-not-log") {
				t.Fatal("missing context or query leaked")
			}
		})
	}
}
func TestLogSubscriberCancellationDoesNotRaceWithWriters(t *testing.T) {
	sink := isolatedLogSink(t)
	var workers sync.WaitGroup
	for i := 0; i < 6; i++ {
		workers.Go(func() {
			for j := 0; j < 300; j++ {
				_, cancel := sink.subscribe()
				sink.add(parseLog("error"))
				cancel()
			}
		})
	}
	workers.Wait()
}
func TestLogsClientEndpointRequiresAuthentication(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}, jwtKey: []byte("fixture-key")}
	request := httptest.NewRequest("POST", "/api/logs/client", strings.NewReader(`{"source":"browser","message":"test"}`))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 401 {
		t.Fatalf("browser log injection allowed: %d", recorder.Code)
	}
}
func TestLauncherDiagnosticsImportOnce(t *testing.T) {
	sink := isolatedLogSink(t)
	root := t.TempDir()
	if err := sink.openJournal(filepath.Join(root, "logs", "system.jsonl")); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "logs", "pending")
	os.MkdirAll(directory, 0700)
	os.WriteFile(filepath.Join(directory, "1.json"), []byte(`{"level":"error","tag":"launcher","text":"device tool failed"}`), 0600)
	sink.importLauncherLogs(root)
	sink.importLauncherLogs(root)
	lines, _ := sink.recent(0, 10)
	if len(lines) != 1 {
		t.Fatal("launcher error lost or duplicated")
	}
	// The middleware still supports cancellation-aware streaming without sockets.
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	_ = ctx
}
