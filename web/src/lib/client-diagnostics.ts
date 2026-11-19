import { MOCK } from "@/lib/mock/enabled";

type Diagnostic = { source: "browser" | "unhandledrejection" | "console" | "network"; message: string; stack: string; page: string; ts: string };
const storageKey = "android_lab_pending_diagnostics";
const MAX_PENDING = 50;
let pending: Diagnostic[] | undefined;
let flushing = false;

function clean(value: string) {
  return value
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED authorization]")
    .replace(/((?:password|api[_-]?key|secret|token)["']?\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,;]+)/gi, "$1[REDACTED]")
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi, "$1REDACTED@")
    .replace(/(https?:\/\/[^\s?#]+)[?#][^\s]*/gi, "$1");
}
function queue() {
  if (!pending) {
    try { pending = JSON.parse(localStorage.getItem(storageKey) || "[]") as Diagnostic[]; }
    catch { pending = []; }
    if (!Array.isArray(pending)) pending = [];
  }
  return pending;
}
function persist() { try { localStorage.setItem(storageKey, JSON.stringify(queue())); } catch { /* Keep the in-memory queue if browser storage is unavailable. */ } }
export function reportClientError(source: Diagnostic["source"], message: string, error?: unknown) {
  if (MOCK || typeof window === "undefined") return;
  const cleanedMsg = clean(message).slice(0, 8000);
  // Ignore offline, server restart, or connection refused drops
  if (
    cleanedMsg.includes("Failed to fetch") ||
    cleanedMsg.includes("NetworkError") ||
    cleanedMsg.includes("Load failed")
  ) {
    return;
  }
  const stack = error instanceof Error ? error.stack || "" : "";
  const q = queue();
  // Deduplicate consecutive identical failures (e.g., background polling ticks while offline)
  if (q.length > 0 && q[q.length - 1].message === cleanedMsg && q[q.length - 1].source === source) {
    return;
  }
  q.push({source, message: cleanedMsg, stack: clean(stack).slice(0, 16000), page: window.location.pathname, ts: new Date().toISOString()});
  if (q.length > MAX_PENDING) {
    q.splice(0, q.length - MAX_PENDING);
  }
  persist();
  void flushClientDiagnostics();
}
export async function flushClientDiagnostics() {
  if (MOCK || typeof window === "undefined" || flushing) return;
  let token: string | null;
  try { token = localStorage.getItem("android_lab_token"); } catch { return; }
  if (!token) return;
  flushing = true;
  try {
    while (queue().length) {
      const response = await fetch("/api/logs/client", {method: "POST", headers: {"Content-Type": "application/json", Authorization: `Bearer ${token}`}, body: JSON.stringify(queue()[0])});
      if (!response.ok) return;
      queue().shift(); persist();
    }
  } catch { /* Retry on reconnect; never recursively report logger failures. */ }
  finally { flushing = false; }
}
