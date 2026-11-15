package androidapk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestToolOutputLimitDuringCopy(t *testing.T) {
	for _, size := range []int{31, 32, 33, 64 << 10} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			output := &boundedOutput{limit: 32}
			// Hide WriterTo to exercise the pipe-reader path used by os/exec.
			reader := struct{ io.Reader }{bytes.NewReader(bytes.Repeat([]byte("x"), size))}
			_, err := io.Copy(output, reader)
			if (err != nil) != (size > output.limit) {
				t.Fatalf("copying %d bytes: error = %v", size, err)
			}
			if output.Len() > output.limit {
				t.Fatalf("retained %d bytes beyond limit %d", output.Len(), output.limit)
			}
			if size <= output.limit && output.Len() != size {
				t.Fatalf("retained %d bytes, want %d", output.Len(), size)
			}
		})
	}
}

func TestMain(m *testing.M) {
	if RunToolProcess() {
		return
	}
	os.Exit(m.Run())
}
func TestIsolatedAPKAnalysis(t *testing.T) {
	path := testAPK(t, []byte(`<manifest package="fixture.app"><application/></manifest>`))
	direct, err := Analyze(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := AnalyzeContext(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if result.SHA256 != direct.SHA256 || result.Package != direct.Package {
		t.Fatal("subprocess changed artifact identity")
	}
}
func TestToolDeadlineKillsAndReapsProcess(t *testing.T) {
	// Controlled local sleep stands in for a parser which does not cooperate
	// with cancellation. The same process runner must kill and reap it.
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep executable unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, sleep, "60")
	started := time.Now()
	_, err = runToolCommand(ctx, cmd, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if cmd.ProcessState == nil || cmd.ProcessState.Success() {
		t.Fatal("child was not killed and reaped")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("hard deadline not enforced")
	}
}
func TestIsolatedAPKCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := AnalyzeContext(ctx, "unused.apk"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
