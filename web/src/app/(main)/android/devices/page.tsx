"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import { ArrowLeft, RefreshCw } from "lucide-react";

import { CopyButton } from "@/components/copy-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { type AndroidEnvironment, androidAPI } from "@/lib/android-api";
import { cn } from "@/lib/utils";

interface ToolMeta {
  name: string;
  category: "bridge" | "decompilers" | "runtime";
  description: string;
  command: string;
}

const toolRegistry: ToolMeta[] = [
  {
    name: "adb",
    category: "bridge",
    description: "Android Debug Bridge: device discovery, APK installation, logcat stream, process inspection.",
    command: "sudo apt install adb",
  },
  {
    name: "apksigner",
    category: "bridge",
    description: "Signature verification (v1, v2, v3, v4 schemes) and signing certificate inspection.",
    command: "sudo apt install apksigner",
  },
  {
    name: "jadx",
    category: "decompilers",
    description: "Dex to Java decompiler for reverse engineering bytecode and analyzing application source.",
    command: "brew install jadx / release binary",
  },
  {
    name: "apktool",
    category: "decompilers",
    description: "Reverse engineering resource decoder, smali disassembler, and manifest reconstructor.",
    command: "brew install apktool / release jar",
  },
  {
    name: "frida",
    category: "runtime",
    description: "Dynamic binary instrumentation toolkit for hooking native methods and tracing cipher calls.",
    command: "pip install frida-tools",
  },
  {
    name: "objection",
    category: "runtime",
    description: "Runtime mobile exploration framework powered by Frida for assessment workflow automation.",
    command: "pip install objection",
  },
];

export default function AndroidDevicesPage() {
  const [environment, setEnvironment] = useState<AndroidEnvironment | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setEnvironment(await androidAPI.environment());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cannot inspect Android environment");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onlineDevices = environment?.devices.filter((d) => d.state === "device") ?? [];
  const readyTools = environment ? Object.values(environment.tools).filter(Boolean).length : 0;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      {/* Header */}
      <div className="space-y-3">
        <Link
          href="/android"
          className="inline-flex items-center gap-1.5 text-muted-foreground text-xs transition-colors hover:text-foreground"
        >
          <ArrowLeft className="size-3.5" />
          <span>Back to applications</span>
        </Link>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="font-semibold text-xl tracking-tight">Device lab</h1>
            <p className="text-muted-foreground text-sm">
              Connected test devices and host-level reverse engineering tool availability for runtime analysis.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="tabular-nums">
              {onlineDevices.length} / {environment?.devices.length ?? 0} online
            </Badge>
            <Button variant="outline" size="sm" disabled={loading} onClick={() => void refresh()} aria-label="Refresh environment">
              <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
              <span>Refresh</span>
            </Button>
          </div>
        </div>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-red-600 text-sm dark:text-red-400">
          <span className="font-semibold">Error:</span> {error}
        </div>
      )}

      {/* Two-column grid */}
      <div className="grid grid-cols-1 gap-4 md:gap-6 lg:grid-cols-2">
        {/* Connected devices */}
        <Card className="gap-0 overflow-hidden p-0">
          <CardHeader className="mb-0 flex-row items-center justify-between border-b p-4">
            <CardTitle className="text-sm">Connected devices</CardTitle>
            <Badge variant="outline" className="tabular-nums">{environment?.devices.length ?? 0} total</Badge>
          </CardHeader>
          <CardContent className="p-0">
            {environment?.message && (
              <div className="border-b bg-muted/30 p-4 text-muted-foreground text-xs">{environment.message}</div>
            )}

            <div className="divide-y divide-border">
              {environment?.devices.map((device) => {
                const isOnline = device.state === "device";
                return (
                  <div key={device.serial} className="flex items-center justify-between gap-4 p-4 transition-colors hover:bg-muted/30">
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-foreground text-sm">
                          {device.model || "Android hardware / emulator"}
                        </span>
                        <Badge variant={isOnline ? "secondary" : "destructive"}>
                          {isOnline ? "Device" : device.state}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 font-mono text-muted-foreground text-xs">
                        <span className="select-all truncate">{device.serial}</span>
                        <CopyButton text={device.serial} label="Copy" size="xs" variant="ghost" className="h-5 px-1.5 text-[10px]" />
                      </div>
                    </div>

                  </div>
                );
              })}

              {environment && !environment.devices.length && (
                <div className="p-8 text-center text-muted-foreground text-sm">
                  No devices detected via ADB. Connect a USB device or launch an emulator.
                </div>
              )}
            </div>

            <div className="border-t bg-muted/20 p-3 text-muted-foreground text-xs leading-normal">
              Discovery runs <code className="rounded bg-muted px-1 py-0.5 font-mono">adb devices -l</code> on the host.
              Offline or unauthorized devices cannot receive runtime instrumentation commands.
            </div>
          </CardContent>
        </Card>

        {/* Tool readiness */}
        <Card className="gap-0 overflow-hidden p-0">
          <CardHeader className="mb-0 flex-row items-center justify-between border-b p-4">
            <CardTitle className="text-sm">Toolchain inventory</CardTitle>
            <Badge variant="outline" className="tabular-nums">
              {environment ? `${readyTools}/${toolRegistry.length} ready` : "Checking…"}
            </Badge>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              {toolRegistry.map((tool) => {
                const isAvailable = environment ? environment.tools[tool.name] : false;
                return (
                  <div key={tool.name} className="flex items-start justify-between gap-4 p-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-foreground text-sm">{tool.name}</span>
                        <Badge variant={isAvailable ? "secondary" : "outline"}>
                          {isAvailable ? "On path" : "Missing"}
                        </Badge>
                      </div>
                      <p className="text-muted-foreground text-xs leading-relaxed">{tool.description}</p>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="border-t bg-muted/20 p-3 text-muted-foreground text-xs leading-normal">
              Built-in static triage runs entirely offline without the Android SDK. Dynamic hooking and Frida
              instrumentation require an ADB device running <code className="rounded bg-muted px-1 py-0.5 font-mono">frida-server</code>.
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Host verification */}
      <Card className="gap-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">Host verification</CardTitle>
          <CopyButton text="adb version && adb devices -l" label="Copy command" size="xs" variant="outline" />
        </div>
        <CardDescription>Verify the ADB bridge, connected devices, and the Frida instrumentation server.</CardDescription>
        <div className="rounded-lg border bg-muted/50 p-4 font-mono text-foreground text-xs leading-relaxed">
          <div className="text-muted-foreground"># Verify ADB bridge and display connected devices</div>
          <div className="mt-1">$ adb version</div>
          <div>$ adb devices -l</div>
          <div className="mt-3 text-muted-foreground"># Verify Frida dynamic instrumentation server</div>
          <div className="mt-1">$ frida-ps -U</div>
        </div>
      </Card>
    </div>
  );
}
