package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"time"

	"github.com/Aiz9/ripple/internal/devicelab"
	"github.com/Aiz9/ripple/internal/traffic"
)

// pollBurp is the single capture source:
// it pulls new proxy exchanges from Burp through its MCP server and records them
// into the traffic store that the UI, traffic_search and finding-evidence read.
// It stops when the store is closed.
//
// Burp's history is addressed by offset, but the operator can clear it mid-session
// (routine, to cut noise), which renumbers every item. A plain offset cursor would
// then point past the end of a now-short list and capture would silently stall for
// the rest of the session. So dedup is by content fingerprint, and the cursor is
// restarted whenever the oldest item is one we have never ingested.
func pollBurp(tr *traffic.Traffic) {
	seen := map[string]struct{}{}
	off := 0
	warned := false
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tr.Done():
			return
		case <-tick.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		c, err := devicelab.DialBurpMCP(ctx, devicelab.BurpMCPURL())
		if err != nil {
			cancel()
			if !warned {
				log.Printf("[traffic] Burp MCP unreachable (%v); no capture until it is up", err)
				warned = true
			}
			continue
		}
		warned = false
		// If the oldest history item is one we have never seen, offsets no longer mean
		// what our cursor assumes (history was cleared/renumbered) — restart paging.
		if head, herr := c.ProxyHistory(ctx, 0, 1); herr == nil && len(head) > 0 {
			if _, ok := seen[burpFingerprint(head[0])]; !ok {
				off = 0
			}
		}
		ex, err := c.ProxyHistory(ctx, off, 500)
		c.Close()
		cancel()
		if err != nil {
			continue
		}
		for _, e := range ex {
			// shortcut: an identical re-request (same bytes) is recorded once. Replays
			// rarely matter for evidence, and this is what lets a history-clear re-page
			// without double-recording; upgrade to a per-item id if Burp MCP exposes one.
			k := burpFingerprint(e)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			tr.Ingest(e.Host, e.Method, e.Request, e.Response, e.TLS)
		}
		off += len(ex)
	}
}

// burpFingerprint identifies one captured exchange by its raw bytes, so dedup
// survives Burp renumbering its history after a clear.
func burpFingerprint(e devicelab.Exchange) string {
	h := sha256.Sum256([]byte(e.Request + "\x00" + e.Response))
	return hex.EncodeToString(h[:])
}
