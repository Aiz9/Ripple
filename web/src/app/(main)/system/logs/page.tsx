"use client";

import * as React from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { http, sseUrl } from "@/lib/api";
import { MOCK } from "@/lib/mock/enabled";
import type { LogLine } from "@/lib/types";
import { cn } from "@/lib/utils";

// Mock demo: no backend SSE, so a few sample log lines are inserted.
const MOCK_LOGS: LogLine[] = [
  {
    seq: 1,
    ts: "2026-07-26T03:55:00Z",
    level: "info",
    tag: "engine",
    text: "Ripple v0.1.0 backend listening on :8787 (workers=3)",
  },
  {
    seq: 2,
    ts: "2026-07-26T03:55:01Z",
    level: "info",
    tag: "config",
    text: "LLM configured from DB: anthropic / claude-opus-4-8",
  },
  {
    seq: 3,
    ts: "2026-07-26T03:56:10Z",
    level: "info",
    tag: "planner",
    text: "task t-acme-web: planning round 3, created intent i-4",
  },
  {
    seq: 4,
    ts: "2026-07-26T03:57:00Z",
    level: "warn",
    tag: "guard",
    text: "block bash: out.evil.example is outside scope",
  },
  {
    seq: 5,
    ts: "2026-07-26T03:57:30Z",
    level: "info",
    tag: "work#1",
    text: "report_finding: Default Credentials (high) saved",
  },
  {
    seq: 6,
    ts: "2026-07-26T03:58:20Z",
    level: "error",
    tag: "work#3",
    text: "intercept: mysqldump matched a destructive-operation rule; awaiting manual approval",
  },
];

const levelTone: Record<LogLine["level"], string> = {
  info: "text-foreground/80",
  warn: "text-amber-600 dark:text-amber-400",
  error: "text-red-600 dark:text-red-400",
};
const levelDot: Record<LogLine["level"], string> = {
  info: "bg-muted-foreground/40",
  warn: "bg-amber-500",
  error: "bg-red-500",
};

function fmtTime(ts: string) {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export default function LogsPage() {
  const [lines, setLines] = React.useState<LogLine[]>([]);
  const [q, setQ] = React.useState("");
  const [level, setLevel] = React.useState<"all" | LogLine["level"]>("all");
  const [paused, setPaused] = React.useState(false);
  const [frozen, setFrozen] = React.useState<LogLine[]>([]);
  const [streamState, setStreamState] = React.useState("Connecting");
  const [historyError, setHistoryError] = React.useState("");
  const [loadingHistory, setLoadingHistory] = React.useState(false);
  const [hasMore, setHasMore] = React.useState(false);
  const bottom = React.useRef<HTMLDivElement>(null);
  const stick = React.useRef(true);
  const visibleLines = paused ? frozen : lines;
  const minSeq = React.useMemo(() => lines.reduce((min,line) => line.seq > 0 && (min===0 || line.seq<min) ? line.seq : min, 0),[lines]);

  // Minimum db_id seen — used as the cursor for loading older history.
  const minDbId = React.useMemo(() => {
    let min = 0;
    for (const l of lines) {
      if (l.db_id && (min === 0 || l.db_id < min)) min = l.db_id;
    }
    return min;
  }, [lines]);

  // Live tail via SSE. on connect, replays whatever is in the ring (includes
  // DB-restored history from the last 100 rows written before restart).
  React.useEffect(() => {
    if (MOCK) {
      setLines(MOCK_LOGS);
      return;
    }

    // Validate authentication and load initial logs via HTTP. If token is invalid or expired,
    // http() intercepts the 401, clears invalid credentials, and redirects to /login.
    http<{ items: LogLine[]; has_more: boolean; source?: string }>("/logs/history?limit=200")
      .then((data) => {
        if (data.items?.length) {
          setLines((prev) => {
            const seen = new Set(prev.map((x) => x.seq));
            const fresh = data.items.filter((x) => !seen.has(x.seq));
            return fresh.length ? [...fresh, ...prev] : prev;
          });
        }
      })
      .catch(() => {
        /* handled by http() or displayed */
      });

    const es = new EventSource(sseUrl("/api/logs/stream?since=0"));
    es.onopen = () => setStreamState("Connected");
    es.onerror = () => {
      setStreamState("Disconnected — reconnecting; history is retained");
      // Check if disconnection was caused by an expired or invalid auth token
      void http("/logs/history?limit=1").catch(() => {});
    };
    es.onmessage = (e) => {
      try {
        const l = JSON.parse(e.data) as LogLine;
        setLines((prev) => (prev.some((x) => x.seq === l.seq) ? prev : [...prev, l]));
      } catch {
        /* ignore malformed frame */
      }
    };
    return () => es.close();
  }, []);

  // Mark "has more" once we have any db_id in view.
  React.useEffect(() => {
    if (minDbId > 1 || minSeq > 1) setHasMore(true);
  }, [minDbId, minSeq]);

  async function loadOlderHistory() {
    if (loadingHistory) return;
    setLoadingHistory(true);
    try {
      setHistoryError("");
      const params = `?before=${minDbId}&before_seq=${minSeq}&limit=200`;
      const data = await http<{ items: LogLine[]; has_more: boolean; source?: string }>(`/logs/history${params}`);
      if (data.items?.length) {
        // Assign synthetic seq numbers below current minimum to keep dedup working.
        setLines((prev) => {
          const minSeq = prev.reduce((m, l) => Math.min(m, l.seq ?? 0), 0);
          const older = data.items.map((l, i) => ({
            ...l,
            seq: data.source === "journal" ? l.seq : minSeq - data.items.length + i,
          }));
          // Prepend, dedup by db_id, cap at 5000.
          const merged = [...older, ...prev];
          const seen = new Set<string>();
          return merged.filter((l) => {
            const key = data.source === "journal" ? `seq:${l.seq}` : l.db_id ? `db:${l.db_id}` : `seq:${l.seq}`;
            if (seen.has(key)) return false;
            seen.add(key); return true;
          });
        });
      }
      setHasMore(data.has_more ?? false);
    } catch (error) {
      setHistoryError(error instanceof Error ? error.message : "Could not load log history");
    } finally {
      setLoadingHistory(false);
    }
  }

  const filtered = React.useMemo(() => {
    const needle = q.trim().toLowerCase();
    return visibleLines.filter(
      (l) =>
        (level === "all" || l.level === level) &&
        (!needle || l.text.toLowerCase().includes(needle) || l.tag.toLowerCase().includes(needle)),
    );
  }, [visibleLines, q, level]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: Log changes intentionally trigger scrolling to the latest entry.
  React.useEffect(() => {
    if (stick.current && !paused) bottom.current?.scrollIntoView();
  }, [filtered, paused]);

  const counts = React.useMemo(() => {
    let warn = 0,
      error = 0;
    for (const l of lines) {
      if (l.level === "warn") warn++;
      else if (l.level === "error") error++;
    }
    return { warn, error, total: lines.length };
  }, [lines]);

  return (
    <div className="flex flex-1 flex-col gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">System logs</h1>
        <p className="text-muted-foreground text-sm">Backend, browser, API, provider, worker, device and launcher diagnostics. Older entries remain in local history.</p>
      </div>
      <div className="flex flex-1 flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Input
            placeholder="Filter (text / tag)…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            className="h-8 max-w-xs"
          />
          <div className="flex gap-1">
            {(["all", "info", "warn", "error"] as const).map((lv) => (
              <Button
                key={lv}
                size="sm"
                variant={level === lv ? "default" : "outline"}
                className="h-8"
                onClick={() => setLevel(lv)}
              >
                {lv === "all" ? "All" : lv}
              </Button>
            ))}
          </div>
          <Button
            size="sm"
            variant={paused ? "default" : "outline"}
            className="h-8"
            onClick={() => { if (!paused) setFrozen(lines); setPaused((p) => !p); }}
          >
            {paused ? "Paused" : "Pause"}
          </Button>
          <Button size="sm" variant="outline" className="h-8" onClick={() => { setLines([]); setFrozen([]); }}>
            Clear
          </Button>
          <span className="ml-auto text-xs text-muted-foreground">
            {counts.total} lines · <span className="text-amber-600 dark:text-amber-400">{counts.warn} Warning</span> ·{" "}
            <span className="text-red-600 dark:text-red-400">{counts.error} Error</span>
          </span>
        </div>

        <p role="status" className="text-sm text-muted-foreground">{MOCK ? "Simulated logs" : streamState}{paused ? " · Display paused; new entries are still captured" : ""}</p>
        {historyError && <p role="alert" className="text-sm text-destructive">{historyError}</p>}
        <div
          onScroll={(e) => {
            const el = e.currentTarget;
            stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
          }}
          className="h-[calc(100vh-14rem)] overflow-auto rounded-lg border bg-card p-2 font-mono text-xs leading-relaxed"
        >
          {hasMore && (
            <div className="flex justify-center py-2">
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                disabled={loadingHistory || paused}
                onClick={loadOlderHistory}
              >
                {loadingHistory ? "Loading…" : "Load earlier logs"}
              </Button>
            </div>
          )}
          {filtered.length === 0 ? (
            <p className="py-10 text-center text-muted-foreground">No logs yet.</p>
          ) : (
            filtered.map((l) => {
              const body =
                l.tag && l.text.startsWith("[" + l.tag + "]") ? l.text.slice(l.tag.length + 2).trimStart() : l.text;
              return (
                <div key={l.seq} className="flex items-start gap-2 px-1 py-0.5 hover:bg-muted/40">
                  <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", levelDot[l.level])} />
                  <span className="shrink-0 tabular-nums text-muted-foreground">{fmtTime(l.ts)}</span>
                  {l.tag && (
                    <span className="shrink-0 rounded bg-muted px-1 text-[10px] text-foreground/70">{l.tag}</span>
                  )}
                  <span className={cn("min-w-0 whitespace-pre-wrap break-words", levelTone[l.level])}>{body}</span>
                </div>
              );
            })
          )}
          <div ref={bottom} />
        </div>
      </div>
    </div>
  );
}
