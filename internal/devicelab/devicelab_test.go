package devicelab

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewValidation(t *testing.T) {
	if _, err := New("bad serial!", "a.b", "", nil); err == nil {
		t.Fatal("bad serial accepted")
	}
	if _, err := New("127.0.0.1:6555", "notapackage", "", nil); err == nil {
		t.Fatal("bad package accepted")
	}
	if _, err := New("127.0.0.1:6555", "a.b.c", "", nil); err != nil {
		t.Fatal(err)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{"simple": "simple", "content://x": "content://x", "a b": "'a b'", "x';y": `'x'\'';y'`, "": "''"}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAllowedPath(t *testing.T) {
	d, _ := New("127.0.0.1:6555", "com.x.y", "", nil)
	ok := []string{"/data/data/com.x.y/shared_prefs/user.xml", "/data/data/com.x.y/databases/a.db", "/sdcard/Android/data/com.x.y/files/x"}
	bad := []string{"/data/data/com.other/shared_prefs/x", "/system/etc/hosts", "/data/data/com.x.y/../com.other/x", "/sdcard/Download/x"}
	for _, p := range ok {
		if !d.allowedPath(p) {
			t.Errorf("expected allowed: %s", p)
		}
	}
	for _, p := range bad {
		if d.allowedPath(p) {
			t.Errorf("expected denied: %s", p)
		}
	}
}

type fakeResolver struct{}

func (fakeResolver) Resolve(role, field string) (string, bool) {
	m := map[string]string{"primary.username": "elliot", "primary.password": "hunter2pass", "primary.totp": "123456"}
	v, ok := m[role+"."+field]
	return v, ok
}
func (fakeResolver) Redact(s string) string {
	return strings.ReplaceAll(s, "{{account:primary.password}}", "***")
}

func TestResolvePlaceholders(t *testing.T) {
	got, err := ResolvePlaceholders("user={{account:primary.username}} pw={{account:primary.password}}", fakeResolver{})
	if err != nil || got != "user=elliot pw=hunter2pass" {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := ResolvePlaceholders("{{account:missing.password}}", fakeResolver{}); err == nil {
		t.Fatal("unknown placeholder accepted")
	}
	if out, _ := ResolvePlaceholders("no placeholders", fakeResolver{}); out != "no placeholders" {
		t.Fatalf("plain text altered: %q", out)
	}
}

func TestInputEscape(t *testing.T) {
	if got := inputEscape("a b&c"); got != `a%sb\&c` {
		t.Fatalf("inputEscape=%q", got)
	}
}

func TestTypeTextClearsWithSeparateKeyArguments(t *testing.T) {
	deletions := 0
	d, _ := New("device", "com.x", "", func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "dumpsys activity activities") {
			return "mResumedActivity: ActivityRecord{123 u0 com.x/.Main t1}", nil
		}
		for _, arg := range args {
			if strings.Contains(arg, "KEYCODE_DEL") {
				if arg != "KEYCODE_DEL" {
					t.Fatalf("multiple key events packed into one argument: %q", arg)
				}
				deletions++
			}
		}
		return "", nil
	})
	_, err := d.TypeText(context.Background(), Node{Editable: true, Text: "old", Bounds: [4]int{0, 0, 100, 100}}, "new", nil)
	if err != nil || deletions != 5 {
		t.Fatalf("deletions=%d err=%v", deletions, err)
	}
}

func TestInputAndCaptureRejectForeignForeground(t *testing.T) {
	d, _ := New("device", "com.x", "", func(_ context.Context, _ string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		if strings.Contains(line, "input ") || strings.Contains(line, "screencap") {
			t.Fatalf("acted on a foreign application: %s", line)
		}
		return "mResumedActivity: ActivityRecord{123 u0 com.other/.Main t1}", nil
	})
	ctx := context.Background()
	if d.Tap(ctx, 10, 10) == nil || d.Swipe(ctx, 10, 10, 20, 20) == nil || d.Key(ctx, "enter") == nil {
		t.Fatal("foreign foreground action accepted")
	}
	if _, err := d.TypeText(ctx, Node{Editable: true}, "fixture", nil); err == nil {
		t.Fatal("foreign foreground input accepted")
	}
	if _, err := d.Screenshot(ctx, nil); err == nil {
		t.Fatal("foreign foreground screenshot accepted")
	}
}

func TestHiddenKeyboardDoesNotNavigateBack(t *testing.T) {
	d, _ := New("device", "com.x", "", func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "input keyevent") {
			t.Fatal("hidden keyboard caused a navigation key")
		}
		return "mInputShown=false", nil
	})
	d.hideKeyboard(context.Background())
}

func TestParseHierarchy(t *testing.T) {
	xml := `<?xml version='1.0'?><hierarchy rotation="0">
<node index="0" class="android.widget.FrameLayout" package="com.x" bounds="[0,0][768,1280]">
  <node index="0" text="Username" resource-id="com.x:id/username" class="android.widget.EditText" package="com.x" clickable="true" password="false" bounds="[10,100][700,160]"/>
  <node index="1" text="" resource-id="com.x:id/password" class="android.widget.EditText" package="com.x" clickable="true" password="true" bounds="[10,200][700,260]"/>
  <node index="2" text="Register" resource-id="com.x:id/register" class="android.widget.Button" package="com.x" clickable="true" bounds="[10,300][700,360]"/>
  <node index="3" text="Welcome back" class="android.widget.TextView" package="com.x" bounds="[10,400][700,440]"/>
</node></hierarchy>`
	s, err := ParseHierarchy(xml, "com.x/.Main")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes) != 3 {
		t.Fatalf("expected 3 actionable nodes, got %d", len(s.Nodes))
	}
	var pw *Node
	for i := range s.Nodes {
		if s.Nodes[i].ID == "password" {
			pw = &s.Nodes[i]
		}
	}
	if pw == nil || !pw.Password || !pw.Editable {
		t.Fatalf("password node not identified: %+v", pw)
	}
	if !s.Contains("welcome back") {
		t.Fatalf("expected visible text captured, texts=%v", s.Texts)
	}
	s2, _ := ParseHierarchy(xml, "com.x/.Main")
	if s.Signature != s2.Signature || s.Signature == "" {
		t.Fatalf("signature not stable")
	}
}

func TestCheckableDrawerItems(t *testing.T) {
	xml := `<hierarchy><node class="android.widget.CheckedTextView" package="com.x" text="Insecure Logging" clickable="false" checkable="true" bounds="[0,100][500,160]"/></hierarchy>`
	s, err := ParseHierarchy(xml, "com.x/.Main")
	if err != nil || len(s.Nodes) != 1 {
		t.Fatalf("checkable item lost: screen=%+v err=%v", s, err)
	}
	d, _ := New("device", "com.x", "", nil)
	n := s.Nodes[0]
	if n.Clickable || !n.Checkable || !d.drawerItem(n) {
		t.Fatalf("checkable drawer item cannot be selected: %+v", n)
	}
	n.Package = "com.other"
	if d.drawerItem(n) {
		t.Fatal("foreign package item accepted")
	}
	n.Package, n.Text = "com.x", "Delete account"
	if d.drawerItem(n) {
		t.Fatal("destructive item accepted")
	}
	n.Text, n.Checkable = "Section heading", false
	if d.drawerItem(n) {
		t.Fatal("non-actionable heading accepted")
	}
}

func TestFindCanaries(t *testing.T) {
	canaries := map[string]string{"ARTEX-CANARY-abcd-1": "hash1"}
	hits := FindCanaries([]byte("prefix ARTEX-CANARY-abcd-1 suffix"), "shared_prefs/user.xml", canaries, nil)
	if len(hits) != 1 || hits[0].Hash != "hash1" || !strings.Contains(hits[0].Excerpt, "ARTEX-CANARY") {
		t.Fatalf("unexpected hits %+v", hits)
	}
	if len(FindCanaries([]byte("nothing here"), "x", canaries, nil)) != 0 {
		t.Fatal("false positive")
	}
}

func TestLeaseSerialization(t *testing.T) {
	l := NewLeases()
	a, ok := l.TryAcquire("dev", "worker-a")
	if !ok {
		t.Fatal("first acquire failed")
	}
	if _, ok := l.TryAcquire("dev", "worker-b"); ok {
		t.Fatal("second acquire must fail while held")
	}
	if l.Holder("dev") != "worker-a" {
		t.Fatalf("holder=%q", l.Holder("dev"))
	}
	// A different serial is independent.
	if _, ok := l.TryAcquire("dev2", "worker-c"); !ok {
		t.Fatal("independent serial should acquire")
	}
	a.Release()
	a.Release() // idempotent
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := l.Acquire(ctx, "dev", "worker-b")
	if err != nil {
		t.Fatalf("acquire after release failed: %v", err)
	}
	b.Release()
}

func TestLeaseAcquireBlocksUntilRelease(t *testing.T) {
	l := NewLeases()
	held, _ := l.TryAcquire("dev", "a")
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		lease, err := l.Acquire(ctx, "dev", "b")
		if lease != nil {
			lease.Release()
		}
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	held.Release()
	if err := <-done; err != nil {
		t.Fatalf("waiter did not acquire after release: %v", err)
	}
}

func TestIsJavaSerialized(t *testing.T) {
	if !IsJavaSerialized([]byte{0xAC, 0xED, 0x00, 0x05, 'x'}) {
		t.Fatal("should detect serialization magic")
	}
	if IsJavaSerialized([]byte("plain")) {
		t.Fatal("false positive")
	}
}
