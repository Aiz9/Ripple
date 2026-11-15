"use client";

import * as React from "react";

import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type BurpMCPState } from "@/lib/api";
import { cn } from "@/lib/utils";

// Burp Suite MCP integration: points the autonomous assessment at a Burp instance
// whose "MCP Server" extension is enabled, so the engine can read decrypted proxy
// history and replay requests. Burp's invisible listener captures proxy-unaware
// apps (Flutter) that ignore the system proxy.
export function BurpMcpCard() {
  const [state, setState] = React.useState<BurpMCPState | null>(null);
  const [url, setUrl] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const s = await api.getBurpMCP();
      setState(s);
      setUrl(s.url);
    } catch {
      // leave empty; the card still renders with the default
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    setBusy(true);
    try {
      const s = await api.setBurpMCP(url.trim());
      setState(s);
      setUrl(s.url);
      toast.success(s.ready ? "Saved — Burp MCP connected" : "Saved — Burp MCP not reachable yet");
    } catch (e) {
      toast.error("Save failed: " + (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    try {
      const s = await api.testBurpMCP(url.trim() || undefined);
      setState((cur) => ({ ...(cur ?? { url: s.url }), ...s }));
      if (s.ready) toast.success(s.detail || "Burp MCP ready");
      else toast.error(s.detail || "Burp MCP not reachable");
    } catch (e) {
      toast.error("Test failed: " + (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const ready = state?.ready;

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6" aria-busy={busy}>
      <CardHeader>
        <CardTitle className="text-base">Burp Suite MCP</CardTitle>
        <CardDescription>
          Autonomous traffic capture &amp; replay via Burp&apos;s MCP Server extension. Enable the extension in Burp
          (MCP tab) and add an invisible proxy listener; the agent reads decrypted history and replays requests.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="burp-mcp-url">MCP server URL</Label>
          <Input
            id="burp-mcp-url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={state?.default ?? "http://127.0.0.1:9876"}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
        </div>

        {state && (ready !== undefined || state.detail) && (
          <div className="flex items-start gap-2 text-sm">
            <span
              className={cn(
                "mt-1.5 size-2 shrink-0 rounded-full",
                ready ? "bg-emerald-500" : "bg-destructive",
              )}
              aria-hidden
            />
            <span className={cn(ready ? "text-muted-foreground" : "text-destructive")}>
              {state.detail ?? (ready ? "Connected" : "Not reachable")}
            </span>
          </div>
        )}

        <div className="flex gap-2">
          <Button onClick={save} disabled={busy || !url.trim()}>
            Save
          </Button>
          <Button variant="outline" onClick={test} disabled={busy}>
            Test connection
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
