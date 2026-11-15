package devicelab

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Denylist of labels the explorer must never activate (destructive or
// session-ending actions), matched case-insensitively against node text/desc/id.
var denyLabels = []string{"delete", "logout", "log out", "sign out", "factory reset", "wipe", "pay", "purchase", "buy", "send money", "transfer", "uninstall", "deactivate", "remove account", "format"}

// primaryActionKeywords label the safe primary buttons exerciseScreen activates
// to drive data-flow challenges (encrypt/hash/save/submit/login …). They are
// also excluded from BFS navigation targets, since exerciseScreen taps them.
var primaryActionKeywords = []string{"execute", "save", "register", "encrypt", "hash", "random", "check", "load", "start", "submit", "run", "send", "test", "login", "go"}

// ExplorerConfig bounds the crawl.
type ExplorerConfig struct {
	MaxSteps   int
	MaxMinutes int
	Resolver   Resolver
	// AlreadyLaunched preserves an attached observer's process.
	AlreadyLaunched bool
}

// ExploreResult summarizes a crawl.
type ExploreResult struct {
	Screens     int
	Steps       int
	FieldsTyped int
	Visited     []string
	Notes       []string
}

func denied(n Node) bool {
	h := strings.ToLower(n.Text + " " + n.Desc + " " + n.ID)
	for _, d := range denyLabels {
		if strings.Contains(h, d) {
			return true
		}
	}
	return false
}

// drawerItem includes CheckedTextView entries whose clickable parent owns the
// action. Tapping their bounds still activates the entry.
func (d *Device) drawerItem(n Node) bool {
	return n.Package == d.Package && (n.Clickable || n.Checkable) && strings.TrimSpace(n.Text) != "" && !denied(n)
}

func (d *Device) drawerVisible(screen *Screen) bool {
	for _, n := range screen.Nodes {
		if n.ID == "design_menu_item_text" && n.Checkable && d.drawerItem(n) {
			return true
		}
	}
	return false
}

// Explore performs a bounded BFS crawl of the approved package: it opens the
// navigation drawer, visits each destination, types a fresh canary into every
// free-text field and activates safe primary buttons. It relaunches on leaving
// the package and never taps denylisted controls. Typing canaries drives the
// data-flow challenges (logging, preferences, SQL, crypto, WebView, network).
func (d *Device) Explore(ctx context.Context, cfg ExplorerConfig, nextCanary func(context string) string) ExploreResult {
	res := ExploreResult{}
	if cfg.MaxSteps == 0 {
		cfg.MaxSteps = 400
	}
	deadline := time.Now().Add(time.Duration(maxInt(cfg.MaxMinutes, 1)) * time.Minute)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	seen := map[string]bool{}
	if !cfg.AlreadyLaunched {
		_ = d.ForceStop(ctx)
		if _, err := d.Launch(ctx); err != nil {
			res.Notes = append(res.Notes, "launch failed: "+err.Error())
			return res
		}
	}
	time.Sleep(2 * time.Second)

	// Record and exercise the pristine launch screen before any drawer probing
	// disturbs it. On login-first apps this types canaries into the form and
	// submits it (driving auth/network/storage flows). Apps whose launch screen
	// has no editable fields (e.g. a drawer home) are only recorded, never acted
	// on, so the drawer walk below behaves exactly as before.
	if launch, err := d.DumpUI(ctx); err == nil {
		if !seen[launch.Signature] {
			seen[launch.Signature] = true
			res.Screens++
		}
		editable, navigable := 0, 0
		for _, n := range launch.Nodes {
			if n.Editable {
				editable++
			}
			if d.navigable(n) {
				navigable++
			}
		}
		labels := []string{}
		for _, n := range launch.Nodes {
			if l := navLabel(n); l != "" && len(labels) < 10 {
				labels = append(labels, l)
			}
		}
		for _, t := range launch.Texts {
			if len(labels) < 10 {
				labels = append(labels, t)
			}
		}
		res.Notes = append(res.Notes, "launch: act="+launch.Activity+" nodes="+itoa(len(launch.Nodes))+" editable="+itoa(editable)+" navigable="+itoa(navigable)+" texts="+itoa(len(launch.Texts))+" labels=["+strings.Join(labels, " | ")+"]")
		if hasEditable(launch) {
			res.FieldsTyped += d.exerciseScreen(ctx, launch, cfg.Resolver, nextCanary)
		}
	} else {
		res.Notes = append(res.Notes, "launch dump failed: "+err.Error())
	}

	// The destinations are reachable from the navigation drawer; enumerate the
	// drawer entries once, then visit each in turn.
	destinations := d.drawerDestinations(ctx)
	// Exercise local data-flow screens before spending the bounded crawl on
	// descriptions and network-only challenges.
	sort.SliceStable(destinations, func(i, j int) bool {
		return localDataFlow(destinations[i]) && !localDataFlow(destinations[j])
	})
	if len(destinations) > 0 {
		res.Notes = append(res.Notes, "drawer destinations: "+itoaN(len(destinations)))
	} else {
		// No navigation drawer (login-first apps, bottom-tab apps, React
		// Native/Flutter trees that label controls via content-desc). Fall back
		// to a bounded breadth-first crawl of the foreground screen so the
		// launch screen is always recorded and its forms/navigation exercised.
		res.Notes = append(res.Notes, "no drawer; foreground BFS fallback")
		d.exploreForeground(ctx, cfg, &res, seen, nextCanary)
		return res
	}
	visit := func(label string) {
		if ctx.Err() != nil || res.Steps >= cfg.MaxSteps {
			return
		}
		if !d.openDrawerTo(ctx, label) {
			return
		}
		res.Steps++
		time.Sleep(1200 * time.Millisecond)
		if !d.InForeground(ctx) {
			_ = d.ForceStop(ctx)
			_, _ = d.Launch(ctx)
			time.Sleep(1500 * time.Millisecond)
			return
		}
		screen, err := d.DumpUI(ctx)
		if err != nil {
			return
		}
		if !seen[screen.Signature] {
			seen[screen.Signature] = true
			res.Screens++
			res.Visited = append(res.Visited, label)
		}
		res.FieldsTyped += d.exerciseScreen(ctx, screen, cfg.Resolver, nextCanary)
	}
	for _, label := range destinations {
		visit(label)
	}
	// A second pass re-exercises data-flow screens now that any prior navigation
	// settled, improving the chance canaries are persisted and logged.
	for _, label := range dataFlowLabels(destinations) {
		visit(label)
	}
	return res
}

// navLabel returns a stable label for a node, preferring visible text, then the
// content description (React Native/Flutter accessibility labels), then the id.
func navLabel(n Node) string {
	for _, s := range []string{n.Text, n.Desc, n.ID} {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// navigable reports whether a node is a safe navigation target to tap during the
// foreground crawl: it belongs to the target app, is clickable, is not a text
// field, is not denylisted, and is not a primary action button (those are driven
// by exerciseScreen). It must carry a label so it can be re-found after a dump.
func (d *Device) navigable(n Node) bool {
	if n.Package != d.Package || !n.Clickable || n.Editable || denied(n) {
		return false
	}
	label := navLabel(n)
	if label == "" {
		return false
	}
	if containsAny(strings.ToLower(n.Text+" "+n.Desc+" "+n.ID), primaryActionKeywords...) {
		return false
	}
	return true
}

// findByLabel locates a navigable node on a freshly dumped screen by its label,
// so a target enumerated earlier can be tapped after the tree has changed.
func (d *Device) findByLabel(s *Screen, label string) *Node {
	for i := range s.Nodes {
		if d.navigable(s.Nodes[i]) && navLabel(s.Nodes[i]) == label {
			return &s.Nodes[i]
		}
	}
	return nil
}

// exploreForeground is the no-drawer fallback crawl. The launch screen has
// already been recorded and exercised by Explore; this breadth-first visits the
// navigation targets the current screen exposes (bottom tabs, menu entries,
// cards), recording and exercising each new screen. It recovers the foreground
// with Launch (am start, no force-stop) so the attached Frida observer survives.
// Destructive controls are never tapped (see denyLabels).
func (d *Device) exploreForeground(ctx context.Context, cfg ExplorerConfig, res *ExploreResult, seen map[string]bool, nextCanary func(string) string) {
	record := func(s *Screen, label string) bool {
		if s == nil || seen[s.Signature] {
			return false
		}
		seen[s.Signature] = true
		res.Screens++
		if label != "" {
			res.Visited = append(res.Visited, label)
		}
		return true
	}
	// Bring the app back to the foreground: drawer probing above may have pressed
	// BACK, and exercising a login form may have navigated away. Launch resumes
	// the existing task without killing the Frida-spawned process.
	cur := d.foreground(ctx)
	if cur == nil {
		res.Notes = append(res.Notes, "no interactive foreground screen")
		return
	}
	if record(cur, "") {
		res.FieldsTyped += d.exerciseScreen(ctx, cur, cfg.Resolver, nextCanary)
		if cur = d.foreground(ctx); cur == nil {
			return
		}
	}

	// Enumerate navigation targets from the current screen.
	var targets []string
	for _, n := range cur.Nodes {
		if d.navigable(n) {
			if l := navLabel(n); !containsStr(targets, l) {
				targets = append(targets, l)
			}
		}
	}

	for _, label := range targets {
		if ctx.Err() != nil || res.Steps >= cfg.MaxSteps {
			return
		}
		cur := d.foreground(ctx)
		if cur == nil {
			continue
		}
		node := d.findByLabel(cur, label)
		if node == nil {
			continue
		}
		if err := d.TapNode(ctx, *node); err != nil {
			continue
		}
		res.Steps++
		time.Sleep(1200 * time.Millisecond)
		screen, err := d.DumpUI(ctx)
		if err != nil || !screen.OwnedBy(d.Package) {
			continue
		}
		if record(screen, label) {
			res.FieldsTyped += d.exerciseScreen(ctx, screen, cfg.Resolver, nextCanary)
		}
	}
}

// foreground returns the current in-package screen, bringing the app forward
// with Launch (no force-stop, preserving any attached Frida session) and giving
// a React Native/Flutter splash time to render before dumping.
func (d *Device) foreground(ctx context.Context) *Screen {
	for attempt := 0; attempt < 3; attempt++ {
		if !d.InForeground(ctx) {
			if _, err := d.Launch(ctx); err != nil {
				return nil
			}
			time.Sleep(1500 * time.Millisecond)
		}
		screen, err := d.DumpUI(ctx)
		if err == nil && screen.OwnedBy(d.Package) && (len(screen.Nodes) > 0 || len(screen.Texts) > 0) {
			return screen
		}
		time.Sleep(1200 * time.Millisecond)
	}
	return nil
}

// hasEditable reports whether a screen exposes at least one editable text field.
func hasEditable(s *Screen) bool {
	for _, n := range s.Nodes {
		if n.Editable {
			return true
		}
	}
	return false
}

func localDataFlow(label string) bool {
	return containsAny(strings.ToLower(label), "logging", "shared", "preference", "crypto", "serial", "sql", "webview")
}

// exerciseScreen types a canary into each editable field and activates the
// screen's primary non-destructive button. Returns the number of fields typed.
func (d *Device) exerciseScreen(ctx context.Context, s *Screen, r Resolver, nextCanary func(string) string) int {
	typed := 0
	hasPassword := false
	// One canary per screen: password/confirm fields must match, and a single
	// marker suffices to prove the data flow for every field on the screen.
	value := nextCanary(s.Activity)
	for _, n := range s.Nodes {
		if n.Editable {
			if n.Password || strings.Contains(strings.ToLower(n.ID), "pass") {
				hasPassword = true
			}
			if _, err := d.TypeText(ctx, n, value, r); err == nil {
				typed++
			}
			// IME "done"/enter triggers editor-action handlers (e.g. logging).
			_ = d.Key(ctx, "enter")
			d.hideKeyboard(ctx)
		}
	}
	// If a login/registration form, also try configured credentials so that
	// authenticated screens are reachable (best-effort; ignored if no account).
	if hasPassword && r != nil {
		d.tryLogin(ctx, s, r)
	}
	// Activate the primary button(s): execute/save/register/encrypt/hash/check/
	// load/start, but never a denylisted control.
	for _, n := range s.Nodes {
		if !n.Clickable || n.Editable || denied(n) {
			continue
		}
		label := strings.ToLower(n.Text + " " + n.Desc + " " + n.ID)
		if containsAny(label, primaryActionKeywords...) {
			_ = d.TapNode(ctx, n)
			time.Sleep(1200 * time.Millisecond)
		}
	}
	return typed
}

// hideKeyboard avoids sending a navigation key when the IME is already hidden.
func (d *Device) hideKeyboard(ctx context.Context) {
	out, err := d.shell(ctx, "dumpsys", "input_method")
	if err == nil && strings.Contains(out, "mInputShown=true") {
		_ = d.Key(ctx, "back")
	}
}

func (d *Device) tryLogin(ctx context.Context, s *Screen, r Resolver) {
	userField, passField := classifyLoginFields(s)
	if userField == nil && passField == nil {
		return
	}

	// First attempt with primary account.
	if d.attemptLogin(ctx, s, r, userField, passField, "primary") {
		return
	}

	// Retry once after a short delay.
	time.Sleep(2 * time.Second)
	if ctx.Err() != nil {
		return
	}
	fresh, err := d.DumpUI(ctx)
	if err != nil {
		return
	}
	userField, passField = classifyLoginFields(fresh)
	if userField == nil && passField == nil {
		return
	}
	if d.attemptLogin(ctx, fresh, r, userField, passField, "primary") {
		return
	}

	// Try secondary account if the resolver supports it.
	if _, ok := r.Resolve("secondary", "username"); !ok {
		return
	}
	time.Sleep(2 * time.Second)
	if ctx.Err() != nil {
		return
	}
	fresh, err = d.DumpUI(ctx)
	if err != nil {
		return
	}
	userField, passField = classifyLoginFields(fresh)
	if userField == nil && passField == nil {
		return
	}
	d.attemptLogin(ctx, fresh, r, userField, passField, "secondary")
}

// classifyLoginFields identifies the username and password fields on a screen
// using ID, hint, desc, password flag, and positional heuristics.
func classifyLoginFields(s *Screen) (userField, passField *Node) {
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.Editable {
			continue
		}
		if isPasswordField(*n) && passField == nil {
			passField = n
		} else if isUsernameField(*n) && userField == nil {
			userField = n
		}
	}
	// Fallback: on a login screen, assign unclassified editable fields by
	// vertical position—the topmost non-password field is the username.
	if (userField == nil || passField == nil) && isLoginScreen(s) {
		for i := range s.Nodes {
			n := &s.Nodes[i]
			if !n.Editable || n == userField || n == passField {
				continue
			}
			if passField == nil && n.Password {
				passField = n
			} else if userField == nil && !n.Password {
				userField = n
			}
		}
	}
	return
}

// attemptLogin types credentials for the given role into the identified fields,
// taps submit, handles an optional OTP screen, and returns whether login
// succeeded.
func (d *Device) attemptLogin(ctx context.Context, s *Screen, r Resolver, userField, passField *Node, role string) bool {
	if userField != nil {
		_, _ = d.TypeText(ctx, *userField, "{{account:"+role+".username}}", r)
		d.hideKeyboard(ctx)
	}
	if passField != nil {
		_, _ = d.TypeText(ctx, *passField, "{{account:"+role+".password}}", r)
		d.hideKeyboard(ctx)
	}

	// Tap the submit button; fall back to the enter key.
	if btn := findSubmitButton(s); btn != nil {
		_ = d.TapNode(ctx, *btn)
	} else {
		_ = d.Key(ctx, "enter")
	}

	time.Sleep(3 * time.Second)

	after, err := d.DumpUI(ctx)
	if err != nil {
		return false
	}

	// Check for an OTP / verification-code field on the post-submit screen.
	for i := range after.Nodes {
		if isOTPField(after.Nodes[i]) {
			_, _ = d.TypeText(ctx, after.Nodes[i], "{{account:"+role+".totp}}", r)
			d.hideKeyboard(ctx)
			if otpBtn := findSubmitButton(after); otpBtn != nil {
				_ = d.TapNode(ctx, *otpBtn)
			} else {
				_ = d.Key(ctx, "enter")
			}
			time.Sleep(2 * time.Second)
			if final, err := d.DumpUI(ctx); err == nil {
				after = final
			}
			break
		}
	}

	return detectLoginSuccess(s, after)
}

// isUsernameField reports whether an editable node looks like a username, email,
// or phone input based on its ID, hint, and content description.
func isUsernameField(n Node) bool {
	low := strings.ToLower(n.ID + " " + n.Hint + " " + n.Desc)
	return containsAny(low, "user", "email", "phone", "account", "login_id")
}

// isPasswordField reports whether an editable node looks like a password or PIN
// input based on the password flag, ID, hint, and content description.
func isPasswordField(n Node) bool {
	if n.Password {
		return true
	}
	low := strings.ToLower(n.ID + " " + n.Hint + " " + n.Desc)
	return containsAny(low, "pass", "pin", "secret")
}

// isOTPField reports whether an editable node looks like an OTP or verification
// code input.
func isOTPField(n Node) bool {
	if !n.Editable {
		return false
	}
	low := strings.ToLower(n.ID + " " + n.Hint + " " + n.Text + " " + n.Desc)
	return containsAny(low, "otp", "code", "verify", "token", "2fa", "mfa")
}

// isLoginScreen reports whether the screen contains login / sign-in indicators.
func isLoginScreen(s *Screen) bool {
	for _, n := range s.Nodes {
		label := strings.ToLower(n.Text + " " + n.Desc + " " + n.ID)
		if containsAny(label, "login", "sign in", "signin", "log in") {
			return true
		}
	}
	for _, t := range s.Texts {
		if containsAny(strings.ToLower(t), "login", "sign in", "signin", "log in") {
			return true
		}
	}
	return false
}

// findSubmitButton locates the most likely login / submit button on the screen.
func findSubmitButton(s *Screen) *Node {
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.Clickable || n.Editable || denied(*n) {
			continue
		}
		label := strings.ToLower(n.Text + " " + n.ID + " " + n.Desc)
		if containsAny(label, "login", "log in", "sign in", "signin", "submit", "next", "continue", "enter", "verify", "go") {
			return n
		}
	}
	return nil
}

// detectLoginSuccess compares screens before and after a login attempt to
// determine whether login succeeded.
func detectLoginSuccess(before, after *Screen) bool {
	// Error text on the post-attempt screen signals failure.
	for _, t := range after.Texts {
		lt := strings.ToLower(t)
		if containsAny(lt, "incorrect", "invalid", "wrong password", "failed", "try again", "error", "denied", "unauthorized") {
			return false
		}
	}
	for _, n := range after.Nodes {
		lt := strings.ToLower(n.Text)
		if containsAny(lt, "incorrect", "invalid", "wrong password", "failed", "try again") {
			return false
		}
	}
	// Different activity or signature means the screen changed.
	if before.Activity != after.Activity {
		return true
	}
	if before.Signature != after.Signature {
		return true
	}
	// Navigation drawer appearance indicates a logged-in state.
	for _, n := range after.Nodes {
		desc := strings.ToLower(n.Desc)
		if containsAny(desc, "navigate up", "open drawer", "navigation drawer") {
			return true
		}
	}
	return false
}

// drawerDestinations opens the navigation drawer and lists its item labels.
func (d *Device) drawerDestinations(ctx context.Context) []string {
	d.openDrawer(ctx)
	screen, err := d.DumpUI(ctx)
	if err != nil {
		return nil
	}
	labels := []string{}
	for _, n := range screen.Nodes {
		if d.drawerItem(n) {
			labels = append(labels, n.Text)
		}
	}
	// Also scrollable: scroll the drawer to reveal more items.
	for i := 0; i < 3; i++ {
		d.Swipe(ctx, 200, 1000, 200, 300)
		time.Sleep(500 * time.Millisecond)
		if more, err := d.DumpUI(ctx); err == nil {
			for _, n := range more.Nodes {
				if d.drawerItem(n) && !containsStr(labels, n.Text) {
					labels = append(labels, n.Text)
				}
			}
		}
	}
	_ = d.Key(ctx, "back")
	return dedupe(labels)
}

func (d *Device) openDrawer(ctx context.Context) {
	// The hamburger is the top-left toolbar nav button.
	if screen, err := d.DumpUI(ctx); err == nil {
		if d.drawerVisible(screen) {
			return
		}
		for _, n := range screen.Nodes {
			desc := strings.ToLower(n.Desc)
			if n.Clickable && (strings.Contains(desc, "navigate up") || strings.Contains(desc, "open") || strings.Contains(desc, "drawer")) {
				_ = d.TapNode(ctx, n)
				time.Sleep(800 * time.Millisecond)
				return
			}
		}
	}
	_ = d.Tap(ctx, 60, 130)
	time.Sleep(800 * time.Millisecond)
}

// openDrawerTo opens the drawer and taps the item whose label matches.
func (d *Device) openDrawerTo(ctx context.Context, label string) bool {
	d.openDrawer(ctx)
	// Enumeration leaves the drawer scrolled near its end. Restore its start
	// before searching so the earlier destinations remain reachable on each pass.
	for i := 0; i < 3 && ctx.Err() == nil; i++ {
		_ = d.Swipe(ctx, 200, 300, 200, 1000)
	}
	for attempt := 0; attempt < 4; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		screen, err := d.DumpUI(ctx)
		if err != nil {
			return false
		}
		for _, n := range screen.Nodes {
			if d.drawerItem(n) && n.Text == label {
				if d.TapNode(ctx, n) != nil {
					return false
				}
				time.Sleep(500 * time.Millisecond)
				after, err := d.DumpUI(ctx)
				return err == nil && !d.drawerVisible(after)
			}
		}
		// Scroll the drawer and retry.
		d.Swipe(ctx, 200, 1000, 200, 400)
		time.Sleep(400 * time.Millisecond)
	}
	return false
}

func dataFlowLabels(all []string) []string {
	out := []string{}
	for _, l := range all {
		low := strings.ToLower(l)
		if containsAny(low, "logging", "shared", "preference", "sql", "crypto", "web", "firebase", "serial", "deep") {
			out = append(out, l)
		}
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func itoaN(n int) string {
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
