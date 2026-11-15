package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/Autumn-27/artex/internal/selfupdate"
)

// Update HTTP boundary handles authentication, mutual exclusion, progress broadcasts, and exit
// requests; selfupdate owns download/verification/replacement.
//
// After staging, exit selfupdate.ExitRestart and let start.sh/start.bat (Docker ENTRYPOINT)
// relaunch the process; the process does not restart itself.

// Close restartCh after ready upgrade/rollback so main exits ExitRestart.
var (
	restartOnce sync.Once
	restartCh   = make(chan struct{})
)

// RestartRequested closes when supervisor relaunch is required.
func RestartRequested() <-chan struct{} { return restartCh }

func requestRestart() { restartOnce.Do(func() { close(restartCh) }) }

// main injects Bootstrap result (success/rollback/discarded stage) at startup so update/check
// accurately explains the previous upgrade outcome.
var (
	bootStateMu sync.Mutex
	bootState   selfupdate.State
)

// SetBootUpdateState is called once by main at startup.
func SetBootUpdateState(st selfupdate.State) {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	bootState = st
}

func bootUpdateState() selfupdate.State {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	return bootState
}

// releaseCache caches GitHub latest-release queries.
//
// Header checks on each page load would exhaust unauthenticated 60/IP/hour quota across tabs,
// preventing real updates later. Cache ordinary checks; explicit Check updates can force refresh.
// Preserve quota while permitting user-requested freshness.
type releaseCache struct {
	mu  sync.Mutex
	rel *selfupdate.Release
	err error
	at  time.Time
	// fetch is test injection; nil queries GitHub normally.
	fetch func(context.Context, *http.Client) (*selfupdate.Release, error)
}

const (
	releaseTTL = 30 * time.Minute
	// Briefly cache failures to avoid a full timeout on every page load while GitHub is unavailable;
	// use short error TTL for quick recovery.
	releaseErrTTL = 2 * time.Minute
	// Version-query timeout is much shorter than NewClient's 30-minute package-download timeout.
	releaseTimeout = 20 * time.Second
)

var relCache = &releaseCache{}

// get returns latest release, without network on cache hits.
//
// Hold lock during fetch so simultaneous tab loads share one result rather than each consuming
// GitHub quota at the highest-risk burst moment.
func (c *releaseCache) get(ctx context.Context, client *http.Client, force bool) (*selfupdate.Release, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !force {
		ttl := releaseTTL
		if c.err != nil {
			ttl = releaseErrTTL
		}
		if !c.at.IsZero() && time.Since(c.at) < ttl {
			return c.rel, c.err
		}
	}

	fetch := c.fetch
	if fetch == nil {
		fetch = selfupdate.FetchLatest
	}
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	rel, err := fetch(ctx, client)
	// Request cancellation from a closed tab is not a GitHub fault; never cache it and inflict
	// an unrelated cancelled error on the next visitor.
	if err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return c.rel, err
	}
	c.rel, c.err, c.at = rel, err, time.Now()
	return rel, err
}

// updateProgress is one frontend progress event.
type updateProgress struct {
	Phase   selfupdate.Phase `json:"phase"`
	Percent int              `json:"percent"` // Percentage meaningful only during download; -1 otherwise.
	Message string           `json:"message"`
	Version string           `json:"version,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// updateHub stores/broadcasts one upgrade's progress to SSE subscribers.
//
// running also acts as exclusion: concurrent apply returns 409, preventing multiple goroutines
// from writing the same artex.new.
type updateHub struct {
	mu      sync.Mutex
	running bool
	cur     updateProgress
	subs    map[chan updateProgress]struct{}
}

var updHub = &updateHub{
	cur:  updateProgress{Phase: selfupdate.PhaseIdle, Percent: -1},
	subs: map[chan updateProgress]struct{}{},
}

// begin acquires upgrade ownership; false when already active.
func (h *updateHub) begin(version string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return false
	}
	h.running = true
	h.cur = updateProgress{Phase: selfupdate.PhaseDownload, Percent: 0, Message: "Preparing…", Version: version}
	h.fanout(h.cur)
	return true
}

// finish ends upgrade; nil error means staged and awaiting restart.
func (h *updateHub) finish(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	if err != nil {
		h.cur = updateProgress{Phase: selfupdate.PhaseFailed, Percent: -1, Message: "Update failed", Error: err.Error(), Version: h.cur.Version}
	} else {
		h.cur = updateProgress{Phase: selfupdate.PhaseStaged, Percent: 100, Message: "New version ready; restarting…", Version: h.cur.Version}
	}
	h.fanout(h.cur)
}

func (h *updateHub) publish(ph selfupdate.Phase, pct int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = updateProgress{Phase: ph, Percent: pct, Message: msg, Version: h.cur.Version}
	h.fanout(h.cur)
}

// fanout requires h.mu; drop updates to full buffered subscriber channels rather than allowing
// blocked SSE clients to stall the actual upgrade.
func (h *updateHub) fanout(p updateProgress) {
	for ch := range h.subs {
		select {
		case ch <- p:
		default:
		}
	}
}

func (h *updateHub) snapshot() (updateProgress, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur, h.running
}

func (h *updateHub) subscribe() (<-chan updateProgress, func()) {
	ch := make(chan updateProgress, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// updateCheck compares latest stable GitHub release with current version.
//
// Frontend may also contact GitHub (CORS *), but backend result is authoritative because
// backend performs downloads. Browser access does not prove server access behind private
// networks/browser-only proxies, so surface connectivity failure at check time instead of
// promising an update that must fail.
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion
	mode := "binary"
	if selfupdate.InDocker() {
		mode = "docker"
	}
	boot := bootUpdateState()
	out := map[string]any{
		"current":     current,
		"mode":        mode,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"has_backup":  selfupdate.HasBackup(),
		"repo":        selfupdate.Repo,
		"boot_notice": boot.Detail,
		"rolled_back": boot.RolledBack,
	}

	// Header uses cache; explicit checks pass force=1.
	force := r.URL.Query().Get("force") != ""
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, force)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}

	latest := rel.TagName
	out["latest"] = latest
	out["notes"] = rel.Body
	out["html_url"] = rel.HTMLURL
	if !rel.PublishedAt.IsZero() {
		out["published_at"] = rel.PublishedAt.Format(time.RFC3339)
	}

	asset := selfupdate.AssetName(latest, runtime.GOOS, runtime.GOARCH)
	out["asset"] = asset
	if a, ok := rel.FindAsset(asset); ok {
		out["asset_available"] = true
		out["size"] = a.Size
	} else {
		out["asset_available"] = false
	}

	cmp, comparable := selfupdate.CompareVersions(current, latest)
	out["comparable"] = comparable
	out["has_update"] = comparable && cmp < 0
	if !comparable {
		// Dev/git-describe-suffixed builds are noncomparable; refuse one-click updates that would
		// overwrite a locally debugged binary with a stable release.
		out["reason"] = fmt.Sprintf("Current version %q is not an official release; one-click updates disabled", current)
	}
	writeJSON(w, 200, out)
}

// updateApply stages new version then requests supervisor restart.
//
// Return 202 immediately; downloading may take minutes beyond reverse-proxy timeouts,
// so background goroutine does work and update/stream reports progress.
func (s *Server) updateApply(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion

	// Use cached release so installed version matches what user reviewed in UI.
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, false)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	cmp, comparable := selfupdate.CompareVersions(current, rel.TagName)
	if !comparable {
		writeErr(w, 400, fmt.Sprintf("Current version %q is not an official release; one-click updates disabled", current))
		return
	}
	if cmp >= 0 {
		writeErr(w, 400, fmt.Sprintf("Already on the latest version %s", current))
		return
	}
	if !updHub.begin(rel.TagName) {
		writeErr(w, 409, "An update is already in progress")
		return
	}

	go func() {
		// Use s.ctx, not request ctx, which cancels as soon as the HTTP response completes,
		// otherwise terminating the download immediately.
		err := selfupdate.Stage(s.ctx, client, rel, current, func(ph selfupdate.Phase, pct int, msg string) {
			updHub.publish(ph, pct, msg)
		})
		updHub.finish(err)
		if err != nil {
			log.Printf("[update] update failed: %v", err)
			return
		}
		log.Printf("[update] %s -> %s staged; exiting to replace binary", current, rel.TagName)
		// Allow final progress event to reach frontend before requesting exit.
		time.Sleep(1500 * time.Millisecond)
		requestRestart()
	}()

	writeJSON(w, 202, map[string]any{"ok": true, "target": rel.TagName})
}

// updateRollback restores backed-up artex.old.
func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request) {
	if _, running := updHub.snapshot(); running {
		writeErr(w, 409, "Update in progress; rollback unavailable")
		return
	}
	if err := selfupdate.Rollback(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	log.Printf("[update] manually rolled back to previous version; exiting to complete switch")
	writeJSON(w, 202, map[string]any{"ok": true})
	go func() {
		time.Sleep(500 * time.Millisecond)
		requestRestart()
	}()
}

// updateStream pushes SSE progress.
func (s *Server) updateStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := updHub.subscribe()
	defer unsub()

	send := func(p updateProgress) {
		b, _ := json.Marshal(p)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	// Send current state first so refreshed pages immediately see active upgrade progress.
	cur, _ := updHub.snapshot()
	send(cur)

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			send(p)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
