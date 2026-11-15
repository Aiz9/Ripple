package devicelab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Node is a compact, LLM-safe view of one actionable or informative UI node.
type Node struct {
	Ref        int    `json:"ref"`
	ID         string `json:"id,omitempty"`
	Text       string `json:"text,omitempty"`
	Desc       string `json:"desc,omitempty"`
	Hint       string `json:"hint,omitempty"`
	Class      string `json:"class"`
	Bounds     [4]int `json:"bounds"`
	Clickable  bool   `json:"clickable,omitempty"`
	Editable   bool   `json:"editable,omitempty"`
	Password   bool   `json:"password,omitempty"`
	Scrollable bool   `json:"scrollable,omitempty"`
	Checkable  bool   `json:"checkable,omitempty"`
	Package    string `json:"-"`
}

// Screen is one parsed UI hierarchy.
type Screen struct {
	Activity  string `json:"activity"`
	Signature string `json:"signature"`
	Nodes     []Node `json:"nodes"`
	// Texts holds visible non-actionable texts (titles, messages, snackbars).
	Texts []string `json:"texts,omitempty"`
	Raw   string   `json:"-"`
}

type xmlNode struct {
	Index      string    `xml:"index,attr"`
	Text       string    `xml:"text,attr"`
	Hint       string    `xml:"hint,attr"`
	ResourceID string    `xml:"resource-id,attr"`
	Class      string    `xml:"class,attr"`
	Package    string    `xml:"package,attr"`
	Desc       string    `xml:"content-desc,attr"`
	Clickable  string    `xml:"clickable,attr"`
	LongClick  string    `xml:"long-clickable,attr"`
	Scrollable string    `xml:"scrollable,attr"`
	Checkable  string    `xml:"checkable,attr"`
	Password   string    `xml:"password,attr"`
	Focusable  string    `xml:"focusable,attr"`
	Bounds     string    `xml:"bounds,attr"`
	Children   []xmlNode `xml:"node"`
}

var boundsPattern = regexp.MustCompile(`^\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]$`)

// ParseHierarchy converts uiautomator XML into a compact Screen.
func ParseHierarchy(raw, activity string) (*Screen, error) {
	start := strings.Index(raw, "<hierarchy")
	end := strings.LastIndex(raw, "</hierarchy>")
	if start < 0 || end < 0 {
		return nil, fmt.Errorf("no UI hierarchy in dump")
	}
	var root struct {
		Nodes []xmlNode `xml:"node"`
	}
	if err := xml.Unmarshal([]byte(raw[start:end+len("</hierarchy>")]), &root); err != nil {
		return nil, fmt.Errorf("parse UI hierarchy: %w", err)
	}
	s := &Screen{Activity: activity, Raw: raw}
	ids := []string{}
	var walk func(n xmlNode)
	walk = func(n xmlNode) {
		m := boundsPattern.FindStringSubmatch(n.Bounds)
		var b [4]int
		if m != nil {
			for i := range b {
				b[i], _ = strconv.Atoi(m[i+1])
			}
		}
		editable := strings.Contains(n.Class, "EditText") || strings.Contains(n.Class, "AutoCompleteTextView")
		clickable := n.Clickable == "true" || n.LongClick == "true"
		checkable := n.Checkable == "true"
		id := strings.TrimPrefix(n.ResourceID, n.Package+":id/")
		if id != "" {
			ids = append(ids, id)
		}
		visible := b[2] > b[0] && b[3] > b[1]
		if visible && (clickable || editable || n.Scrollable == "true" || checkable) {
			s.Nodes = append(s.Nodes, Node{Ref: len(s.Nodes), ID: id, Text: clip(n.Text, 120), Desc: clip(n.Desc, 120), Hint: clip(n.Hint, 120), Class: shortClass(n.Class), Bounds: b, Clickable: clickable, Editable: editable, Password: n.Password == "true", Scrollable: n.Scrollable == "true", Checkable: checkable, Package: n.Package})
		} else if visible && strings.TrimSpace(n.Text) != "" && len(s.Texts) < 40 {
			s.Texts = append(s.Texts, clip(n.Text, 200))
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, n := range root.Nodes {
		walk(n)
	}
	sort.Strings(ids)
	h := sha256.Sum256([]byte(activity + "\x00" + strings.Join(dedupe(ids), ",")))
	s.Signature = hex.EncodeToString(h[:8])
	return s, nil
}

func dedupe(xs []string) []string {
	out := xs[:0:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func shortClass(c string) string {
	if i := strings.LastIndexByte(c, '.'); i >= 0 {
		return c[i+1:]
	}
	return c
}

// DumpUI captures the current hierarchy.
func (d *Device) DumpUI(ctx context.Context) (*Screen, error) {
	var raw string
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		raw, err = d.ADB(ctx, 20*time.Second, "exec-out", "uiautomator", "dump", "/dev/tty")
		if err == nil && strings.Contains(raw, "<hierarchy") {
			break
		}
		time.Sleep(700 * time.Millisecond)
	}
	if err != nil && !strings.Contains(raw, "<hierarchy") {
		return nil, fmt.Errorf("uiautomator dump failed: %w", err)
	}
	return ParseHierarchy(raw, d.CurrentActivity(ctx))
}

// OwnedBy reports whether any node belongs to the approved package.
func (s *Screen) OwnedBy(pkg string) bool {
	for _, n := range s.Nodes {
		if n.Package == pkg {
			return true
		}
	}
	return strings.HasPrefix(s.Activity, pkg+"/")
}

// Contains reports whether any visible text or node label contains sub.
func (s *Screen) Contains(sub string) bool {
	sub = strings.ToLower(sub)
	for _, t := range s.Texts {
		if strings.Contains(strings.ToLower(t), sub) {
			return true
		}
	}
	for _, n := range s.Nodes {
		if strings.Contains(strings.ToLower(n.Text+" "+n.Desc+" "+n.ID), sub) {
			return true
		}
	}
	return false
}

func center(b [4]int) (int, int) { return (b[0] + b[2]) / 2, (b[1] + b[3]) / 2 }

// Tap taps the center of a node or explicit coordinates inside the screen.
func (d *Device) Tap(ctx context.Context, x, y int) error {
	if x < 0 || y < 0 || x > 10000 || y > 10000 {
		return fmt.Errorf("coordinates out of range")
	}
	if pkg, ok := d.InteractAllowed(ctx); !ok {
		return d.interactBlockedErr(pkg)
	}
	_, err := d.shell(ctx, "input", "tap", strconv.Itoa(x), strconv.Itoa(y))
	return err
}

// TapNode taps a parsed node.
func (d *Device) TapNode(ctx context.Context, n Node) error {
	x, y := center(n.Bounds)
	return d.Tap(ctx, x, y)
}

// Swipe performs a bounded swipe.
func (d *Device) Swipe(ctx context.Context, x1, y1, x2, y2 int) error {
	for _, v := range []int{x1, y1, x2, y2} {
		if v < 0 || v > 10000 {
			return fmt.Errorf("coordinates out of range")
		}
	}
	if pkg, ok := d.InteractAllowed(ctx); !ok {
		return d.interactBlockedErr(pkg)
	}
	_, err := d.shell(ctx, "input", "swipe", strconv.Itoa(x1), strconv.Itoa(y1), strconv.Itoa(x2), strconv.Itoa(y2), "300")
	return err
}

// Key sends one of a fixed set of key events.
func (d *Device) Key(ctx context.Context, name string) error {
	code := map[string]string{"back": "4", "home": "3", "enter": "66", "tab": "61", "escape": "111"}[name]
	if code == "" {
		return fmt.Errorf("unsupported key %q", name)
	}
	if pkg, ok := d.InteractAllowed(ctx); !ok {
		return d.interactBlockedErr(pkg)
	}
	_, err := d.shell(ctx, "input", "keyevent", code)
	return err
}

var placeholderPattern = regexp.MustCompile(`\{\{account:([a-z][a-z0-9_-]{0,39})\.(username|password|totp)\}\}`)

// Resolver turns credential placeholders into values at the tool boundary.
// Values never leave devicelab; Redact removes them from any returned text.
type Resolver interface {
	Resolve(role, field string) (string, bool)
	Redact(text string) string
}

// ResolvePlaceholders replaces {{account:role.field}} placeholders.
func ResolvePlaceholders(text string, r Resolver) (string, error) {
	var missing string
	out := placeholderPattern.ReplaceAllStringFunc(text, func(m string) string {
		parts := placeholderPattern.FindStringSubmatch(m)
		if r == nil {
			missing = m
			return m
		}
		v, ok := r.Resolve(parts[1], parts[2])
		if !ok {
			missing = m
			return m
		}
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("unknown credential placeholder %s", missing)
	}
	if strings.Contains(out, "{{") {
		return "", fmt.Errorf("malformed placeholder")
	}
	return out, nil
}

// inputEscape encodes text for `input text`, which splits on spaces and treats
// shell metacharacters specially.
func inputEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ':
			b.WriteString("%s")
		case strings.ContainsRune(`()<>|;&*\~"'$`+"`"+`!?#[]{}`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TypeText focuses a node and types text; placeholders are resolved here and
// nowhere else. The returned string is safe to log.
func (d *Device) TypeText(ctx context.Context, n Node, text string, r Resolver) (string, error) {
	if n.Package != "" && n.Package != d.Package {
		return "", fmt.Errorf("input node belongs to another package")
	}
	if !n.Editable {
		return "", fmt.Errorf("node %d is not an editable field", n.Ref)
	}
	value, err := ResolvePlaceholders(text, r)
	if err != nil {
		return "", err
	}
	if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("text must be a single line of at most 512 characters")
	}
	if err := d.TapNode(ctx, n); err != nil {
		return "", err
	}
	// Clear existing content: move to end and delete a bounded number of chars.
	_, _ = d.shell(ctx, "input", "keyevent", "KEYCODE_MOVE_END")
	deleteKeys := []string{"input", "keyevent"}
	for i := 0; i < min(len(n.Text)+2, 512); i++ {
		deleteKeys = append(deleteKeys, "KEYCODE_DEL")
	}
	_, _ = d.shell(ctx, deleteKeys...)
	if _, err := d.ADB(ctx, 20*time.Second, "shell", "input", "text", shellQuote(inputEscape(value))); err != nil {
		return "", err
	}
	if r != nil {
		return r.Redact(text), nil
	}
	return text, nil
}

// Screenshot captures a PNG and blacks out password-field bounds. A window with
// FLAG_SECURE yields an empty capture; callers treat empty bytes as "blocked"
// rather than an error (see ScreenCaptureBlocked).
func (d *Device) Screenshot(ctx context.Context, mask []Node) ([]byte, error) {
	if pkg, ok := d.InteractAllowed(ctx); !ok {
		return nil, d.interactBlockedErr(pkg)
	}
	raw, err := d.ADB(ctx, 20*time.Second, "exec-out", "screencap", "-p")
	if err != nil && raw == "" {
		return nil, fmt.Errorf("screencap: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil // FLAG_SECURE: capture refused.
	}
	img, err := png.Decode(strings.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode screenshot: %w", err)
	}
	needs := false
	for _, n := range mask {
		if n.Password {
			needs = true
		}
	}
	if !needs {
		return []byte(raw), nil
	}
	rgba := image.NewRGBA(img.Bounds())
	draw.Draw(rgba, rgba.Bounds(), img, image.Point{}, draw.Src)
	for _, n := range mask {
		if n.Password {
			draw.Draw(rgba, image.Rect(n.Bounds[0], n.Bounds[1], n.Bounds[2], n.Bounds[3]), &image.Uniform{color.Black}, image.Point{}, draw.Src)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, rgba); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ScreenCaptureBlocked reports whether a capture indicates FLAG_SECURE: either
// an empty result (capture refused) or a (near) single-color image.
func ScreenCaptureBlocked(pngBytes []byte) bool {
	return len(pngBytes) == 0 || MostlyBlank(pngBytes)
}

// MostlyBlank reports whether a PNG is (nearly) a single color, which is how
// FLAG_SECURE windows appear in screencap output.
func MostlyBlank(pngBytes []byte) bool {
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return false
	}
	b := img.Bounds()
	// Ignore the status and navigation bars (top/bottom 8 %).
	top, bottom := b.Min.Y+b.Dy()*8/100, b.Max.Y-b.Dy()*8/100
	counts := map[uint32]int{}
	total := 0
	for y := top; y < bottom; y += 7 {
		for x := b.Min.X; x < b.Max.X; x += 7 {
			r, g, bl, _ := img.At(x, y).RGBA()
			counts[(r>>12)<<8|(g>>12)<<4|bl>>12]++
			total++
		}
	}
	best := 0
	for _, c := range counts {
		best = max(best, c)
	}
	return total > 0 && best*100/total >= 97
}
