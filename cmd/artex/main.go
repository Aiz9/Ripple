// Command artex runs the ARTEX backend: the PostgreSQL graph stores,
// the event-driven exploration engine, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/Autumn-27/artex/internal/androidapk"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/internal/agent"
	"github.com/Autumn-27/artex/internal/config"
	"github.com/Autumn-27/artex/internal/selfupdate"
	"github.com/Autumn-27/artex/internal/server"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>". Defaults to "dev" for local builds.
var version = "dev"

const banner = `
  RIPPLE
  Android application security testing · Based on ARTEX
`

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Print(banner)
	fmt.Println("  APK analysis · Device lab · Agent assessments")
	fmt.Printf("  Version %s  ·  %s/%s  ·  %s  ·  Listening on %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

// isolateDataModule drops a go.mod into the data directory so it becomes a
// separate, empty Go module. The data dir sits inside the source tree and agents
// write arbitrary files into task workspaces under it — including stray .go
// scripts — which would otherwise break `go build/vet/test ./...`.
func isolateDataModule(dir string) {
	marker := filepath.Join(dir, "go.mod")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err == nil {
		_ = os.WriteFile(marker, []byte("module ripple.local/runtime-data\n"), 0o644)
	}
}

// main only maps run's result onto the process exit code. The exit code is part
// of the update protocol — the supervising start script reads it to decide
// whether to relaunch us (see selfupdate.ExitRestart) — so the body has to live
// in a function that can *return* rather than os.Exit past its own defers.
func main() {
	if androidapk.RunToolProcess() {
		return
	}
	os.Exit(run())
}

func run() int {
	var (
		addr    = flag.String("addr", ":8797", "HTTP listen address")
		dataDir = flag.String("data", filepath.Join(config.BaseDir(), "data"), "application data directory (default: data/ next to the executable)")
		proxy   = flag.String("proxy", "127.0.0.1:8798", "traffic recording proxy address (empty to disable)")
	)
	flag.Parse()
	isolateDataModule(*dataDir)

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCaptureAt(*dataDir)

	// Self-update bootstrap: swap in a staged binary, or count a post-swap boot
	// attempt and roll back if the new build keeps dying. Must run before we open
	// the stores or bind a port — this may end with "exit and let the start script
	// relaunch me", and there is no point paying for either first.
	action, upState := selfupdate.Bootstrap()
	server.SetBootUpdateState(upState)
	if action == selfupdate.Restart {
		return selfupdate.ExitRestart
	}

	// surface which config file the binary reads (absolute, so `go run`'s relative
	// "config.json" — resolved against the CWD — is unambiguous).
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf("[config] Config file: %s", cfgPath)
	} else {
		log.Printf("[config] Config file: %s (not found; trying ANDROIDLAB_PG_DSN only)", cfgPath)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Fatalf("open stores: %v", err)
	}
	defer mgr.Close()

	// Surviving this long means a freshly swapped-in build actually works, so drop
	// the upgrade marker and stop counting attempts. Until it fires, every boot
	// increments the count and a build that keeps dying gets rolled back.
	settle := time.AfterFunc(selfupdate.SettleDelay, selfupdate.Settle)
	defer settle.Stop()

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf("[config] Skills directory: %s", skillDir)
	keyDir := filepath.Join(config.BaseDir(), "identity")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		log.Fatalf("create Ripple identity directory: %v", err)
	}
	srv := server.New(ctx, mgr, skillDir, *dataDir, keyDir)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("ARTEX %s backend listening on %s (data=%s, workers=%d)", version, *addr, *dataDir, mgr.Workers())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	// Two ways out: a signal (normal stop → exit 0, the start script stops looping)
	// or a staged update / rollback (→ exit 75, the script relaunches us and the
	// bootstrap above installs the new build).
	code := 0
	select {
	case <-ctx.Done():
	case <-server.RestartRequested():
		code = selfupdate.ExitRestart
		shutdown(agent.AbortShutdown)
	case err := <-serveErr:
		log.Printf("serve: %v", err)
		code = 1
		shutdown(agent.AbortShutdown)
	}

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		_ = httpSrv.Close() // Cancel handlers which exceeded the graceful deadline.
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer drainCancel()
	if err := srv.WaitForShutdown(drainCtx); err != nil {
		log.Printf("shutdown: background jobs did not finish before the deadline: %v", err)
	}
	return code
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}
