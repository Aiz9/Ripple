package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// referencedScript is a local script file a pending Bash approval would execute,
// surfaced in the approval detail so the operator can review what actually runs
// (e.g. `python3 final.py` shows final.py's contents, not just the command).
type referencedScript struct {
	Path      string `json:"path"`
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

const (
	maxScriptBytes = 64 * 1024 // per file; larger files are shown truncated
	maxScripts     = 5         // cap files surfaced per approval
)

var (
	// Interpreter invocation: the script path is the first argument after it.
	scriptInterpRe = regexp.MustCompile(`(?i)\b(?:python3?|bash|sh|node|nodejs|ruby|perl|php|lua|Rscript)\s+("[^"]+"|'[^']+'|[^\s;&|<>]+)`)
	// A token that names a script by extension (also catches ./run.sh style args).
	scriptExtRe = regexp.MustCompile(`(?i)\.(py|sh|bash|js|mjs|cjs|ts|rb|pl|php|lua|r)$`)
	// A leading `cd <dir>` sets the base directory for relative script paths.
	scriptCdRe = regexp.MustCompile(`(?:^|[;&|])\s*cd\s+("[^"]+"|'[^']+'|[^\s;&|<>]+)`)
)

// referencedScripts returns the local script files a pending tool call would run.
// Reads are confined to dataDir so a crafted command cannot turn the approval view
// into an arbitrary-file reader. Only Bash/shell commands carry a script.
func referencedScripts(toolName string, toolInput json.RawMessage, dataDir string) []referencedScript {
	var in struct {
		Command string `json:"command"`
		Text    string `json:"text"`
	}
	_ = json.Unmarshal(toolInput, &in)
	cmd := in.Command
	if cmd == "" {
		cmd = in.Text
	}
	switch toolName {
	case "Bash", "shell_open", "shell_send":
	default:
		return nil
	}
	if strings.TrimSpace(cmd) == "" {
		return nil
	}

	root, err := filepath.Abs(dataDir)
	if err != nil {
		return nil
	}
	root = filepath.Clean(root)

	base := root
	if m := scriptCdRe.FindStringSubmatch(cmd); m != nil {
		if d := unquoteToken(m[1]); d != "" {
			if filepath.IsAbs(d) {
				base = filepath.Clean(d)
			} else {
				base = filepath.Clean(filepath.Join(root, d))
			}
		}
	}

	// Collect candidate script tokens, de-duplicated, preserving order.
	seen := map[string]bool{}
	var out []referencedScript
	add := func(tok string) {
		tok = unquoteToken(tok)
		if tok == "" || !scriptExtRe.MatchString(tok) {
			return
		}
		p := tok
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		p = filepath.Clean(p)
		if seen[p] || len(out) >= maxScripts {
			return
		}
		seen[p] = true
		out = append(out, readScript(root, p))
	}
	for _, m := range scriptInterpRe.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	for _, tok := range regexp.MustCompile(`[\s;&|<>()=]+`).Split(cmd, -1) {
		add(tok)
	}
	return out
}

// readScript reads one candidate, refusing anything outside root or not a regular
// file, and bounding the content size.
func readScript(root, p string) referencedScript {
	rs := referencedScript{Path: p}
	if !withinDir(root, p) {
		rs.Error = "outside task workspace"
		return rs
	}
	info, err := os.Stat(p)
	if err != nil {
		rs.Error = "not found"
		return rs
	}
	if !info.Mode().IsRegular() {
		rs.Error = "not a regular file"
		return rs
	}
	f, err := os.Open(p)
	if err != nil {
		rs.Error = "unreadable"
		return rs
	}
	defer f.Close()
	buf := make([]byte, maxScriptBytes+1)
	n, _ := f.Read(buf)
	if n > maxScriptBytes {
		n = maxScriptBytes
		rs.Truncated = true
	}
	rs.Content = string(buf[:n])
	return rs
}

func unquoteToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	return s
}

// withinDir reports whether p is root itself or nested under it.
func withinDir(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
