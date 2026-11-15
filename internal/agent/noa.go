package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noaadapter"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa is model-driven context compaction introduced in norma v0.4.0, exposed as an
// experimental system-setting switch. It is exclusive with built-in compaction. noaadapter.Enable
// installs the Compactor, Compress tool, and three persistent prompts together; without it,
// built-in compaction remains active. Each agent reads noaEnabledFn once per run, so changes
// affect only later runs and do not require reconstructing the agent.

// enableNoa attaches noa when enabled. archiveRoot is the durable archive base, using global
// workDir so all agents write under <workDir>/noa rather than scattered task/intent directories.
// A globally unique sessionID names the archive subdirectory without collisions.
//
// Experimental setup failure must not interrupt real tasks: warn through onWarn and fall back.
// On success clear opts.Compaction to avoid agentcore's dual-manager warning.
func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("Failed to enable noa compaction; falling back to built-in compaction:" + err.Error())
		}
		return
	}
	// Compactor overrides Compaction; clear the latter to avoid a warning on every call.
	opts.Compaction = nil
}
