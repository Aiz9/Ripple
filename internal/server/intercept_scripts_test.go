package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bashInput(cmd string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return b
}

func TestReferencedScriptsReadsCdScript(t *testing.T) {
	data := t.TempDir()
	iter := filepath.Join(data, "tasks", "774", "i4644")
	if err := os.MkdirAll(iter, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(iter, "final.py"), []byte("print('pwn')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := referencedScripts("Bash", bashInput("cd "+iter+" && python3 final.py 2>&1"), data)
	if len(got) != 1 {
		t.Fatalf("want 1 script, got %d: %+v", len(got), got)
	}
	if got[0].Error != "" || !strings.Contains(got[0].Content, "print('pwn')") {
		t.Fatalf("script not read: %+v", got[0])
	}
}

func TestReferencedScriptsRejectsOutsideWorkspace(t *testing.T) {
	data := t.TempDir()
	// A readable file that exists but lives outside the data dir must not be shown.
	outside := filepath.Join(t.TempDir(), "secret.sh")
	os.WriteFile(outside, []byte("rm -rf /\n"), 0o644)
	got := referencedScripts("Bash", bashInput("bash "+outside), data)
	if len(got) != 1 || got[0].Content != "" || got[0].Error != "outside task workspace" {
		t.Fatalf("outside-workspace script should be refused, got: %+v", got)
	}
}

func TestReferencedScriptsIgnoresNonShellTools(t *testing.T) {
	if got := referencedScripts("Write", bashInput("python3 x.py"), t.TempDir()); got != nil {
		t.Fatalf("non-shell tool should yield no scripts, got %+v", got)
	}
}

func TestReferencedScriptsTruncates(t *testing.T) {
	data := t.TempDir()
	big := strings.Repeat("a", maxScriptBytes+100)
	os.WriteFile(filepath.Join(data, "run.sh"), []byte(big), 0o644)
	got := referencedScripts("Bash", bashInput("sh run.sh"), data)
	if len(got) != 1 || !got[0].Truncated || len(got[0].Content) != maxScriptBytes {
		t.Fatalf("expected truncated content of %d bytes, got %+v (len=%d)", maxScriptBytes, got[0].Truncated, len(got[0].Content))
	}
}
