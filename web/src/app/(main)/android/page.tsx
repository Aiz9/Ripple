"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import {
  ArrowRight,
  Download,
  Loader2,
  Play,
  RefreshCw,
  Search,
  Upload,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { type AndroidApp, type AndroidEnvironment, androidAPI } from "@/lib/android-api";
import { api } from "@/lib/api";
import { MOCK } from "@/lib/mock/enabled";
import type { Task } from "@/lib/types";
import { cn } from "@/lib/utils";

const DANGEROUS_PERMISSIONS = new Set([
  "android.permission.READ_CALENDAR",
  "android.permission.WRITE_CALENDAR",
  "android.permission.CAMERA",
  "android.permission.READ_CONTACTS",
  "android.permission.WRITE_CONTACTS",
  "android.permission.GET_ACCOUNTS",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.ACCESS_BACKGROUND_LOCATION",
  "android.permission.RECORD_AUDIO",
  "android.permission.READ_PHONE_STATE",
  "android.permission.READ_PHONE_NUMBERS",
  "android.permission.CALL_PHONE",
  "android.permission.ANSWER_PHONE_CALLS",
  "android.permission.READ_CALL_LOG",
  "android.permission.WRITE_CALL_LOG",
  "android.permission.ADD_VOICEMAIL",
  "android.permission.USE_SIP",
  "android.permission.BODY_SENSORS",
  "android.permission.BODY_SENSORS_BACKGROUND",
  "android.permission.SEND_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.READ_SMS",
  "android.permission.RECEIVE_WAP_PUSH",
  "android.permission.RECEIVE_MMS",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.ACCESS_MEDIA_LOCATION",
  "android.permission.READ_MEDIA_AUDIO",
  "android.permission.READ_MEDIA_IMAGES",
  "android.permission.READ_MEDIA_VIDEO",
  "android.permission.POST_NOTIFICATIONS",
  "android.permission.USE_BIOMETRIC",
  "android.permission.USE_FINGERPRINT",
  "android.permission.BLUETOOTH_CONNECT",
  "android.permission.BLUETOOTH_SCAN",
  "android.permission.BLUETOOTH_ADVERTISE",
  "android.permission.NEARBY_WIFI_DEVICES",
]);

function exportReport(app: AndroidApp) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(app, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `android-${app.id.slice(0, 12)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function AndroidPage() {
  const router = useRouter();
  const fileInput = useRef<HTMLInputElement>(null);
  const [apps, setApps] = useState<AndroidApp[]>([]);
  const [environment, setEnvironment] = useState<AndroidEnvironment | null>(null);
  const [selectedID, setSelectedID] = useState("");
  const [tasks, setTasks] = useState<Task[]>([]);
  const [tasksError, setTasksError] = useState("");
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const [triageFilter, setTriageFilter] = useState("all");
  const [componentFilter, setComponentFilter] = useState("all");
  const [componentSearch, setComponentSearch] = useState("");
  const [permissionSearch, setPermissionSearch] = useState("");

  const selected = apps.find((app) => app.id === selectedID) ?? apps[0];
  const onlineDevices = environment?.devices.filter((item) => item.state === "device") ?? [];
  const assessmentTasks = selected
    ? tasks.filter((task) => task.description?.includes(`[Android APK: ${selected.id}]`))
    : [];

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    const results = await Promise.allSettled([
      androidAPI.apps(),
      androidAPI.environment(),
      api.tasks(),
    ]);
    if (results[0].status === "fulfilled") setApps(results[0].value);
    else setError(results[0].reason instanceof Error ? results[0].reason.message : "Cannot load Android applications");
    if (results[1].status === "fulfilled") setEnvironment(results[1].value);
    else toast.error("Device discovery failed. Check backend connection.");
    if (results[2].status === "fulfilled") {
      setTasks(results[2].value.tasks);
      setTasksError("");
    } else setTasksError("Could not load assessment history.");
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // startAPKTask creates a main-engine APK security task (the single assessment
  // path) and routes to it. The backend seeds the MASVS phase goals.
  const startAPKTask = useCallback(
    async (apkId: string) => {
      setCreating(true);
      try {
        const task = await androidAPI.createTask({ apkId });
        router.push(`/function/tasks/detail?id=${encodeURIComponent(task.id)}`);
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "Could not create APK task");
      } finally {
        setCreating(false);
      }
    },
    [router],
  );

  async function upload(file?: File) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk") || file.size > 256 * 1024 * 1024) {
      toast.error("Choose an .apk file up to 256 MiB.");
      return;
    }
    setUploading(true);
    try {
      const app = await androidAPI.upload(file);
      setApps((current) => [app, ...current.filter((item) => item.id !== app.id)]);
      setSelectedID(app.id);
      setError("");
      toast.success("APK uploaded. Static triage complete.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "APK upload failed");
    } finally {
      setUploading(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  const filteredComponents = useMemo(() => {
    if (!selected) return [];
    return selected.report.components.filter((c) => {
      const matchesKind = componentFilter === "all" || c.kind.toLowerCase() === componentFilter.toLowerCase();
      const matchesQuery =
        !componentSearch ||
        c.name.toLowerCase().includes(componentSearch.toLowerCase()) ||
        c.permission.toLowerCase().includes(componentSearch.toLowerCase());
      return matchesKind && matchesQuery;
    });
  }, [selected, componentFilter, componentSearch]);

  const filteredFindings = useMemo(() => {
    if (!selected) return [];
    return selected.report.findings.filter((f) => {
      return triageFilter === "all" || f.severity.toLowerCase() === triageFilter.toLowerCase();
    });
  }, [selected, triageFilter]);

  const filteredPermissions = useMemo(() => {
    if (!selected) return [];
    const unique = [...new Set(selected.report.permissions)];
    if (!permissionSearch) return unique;
    return unique.filter((p) => p.toLowerCase().includes(permissionSearch.toLowerCase()));
  }, [selected, permissionSearch]);

  const statCards = [
    {
      label: "Applications",
      value: loading && !apps.length ? "—" : apps.length,
      detail: "Unique package builds",
    },
    {
      label: "Observations",
      value: loading && !apps.length ? "—" : apps.reduce((sum, app) => sum + app.report.findings.length, 0),
      detail: "Manifest triage findings",
    },
    {
      label: "Online devices",
      value: loading && !apps.length ? "—" : onlineDevices.length,
      detail: onlineDevices.length > 0 ? "ADB device connected" : "No device authorized",
    },
    {
      label: "Tool readiness",
      value: environment
        ? `${Object.values(environment.tools).filter(Boolean).length}/${Object.keys(environment.tools).length}`
        : "—",
      detail: "Bridge & analysis toolchain",
    },
  ];

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">Applications</h1>
          <p className="text-muted-foreground text-sm">
            Static binary triage, manifest inspection, IPC component analysis, and evidence-backed assessments.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" disabled={loading} onClick={() => void refresh()} aria-label="Refresh workspace">
            <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
            <span>Refresh</span>
          </Button>
          <Button variant="accent" size="sm" disabled={uploading} onClick={() => fileInput.current?.click()}>
            {uploading ? <Loader2 className="size-3.5 animate-spin" /> : <Upload className="size-3.5" />}
            <span>{uploading ? "Analyzing…" : "Upload APK"}</span>
          </Button>
          <input
            ref={fileInput}
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            className="hidden"
            aria-label="Upload Android APK"
            onChange={(event) => void upload(event.target.files?.[0])}
          />
        </div>
      </div>

      {MOCK && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-amber-700 text-sm dark:text-amber-400">
          <span className="font-semibold">Demo workspace:</span> simulated application data. Start the backend host for
          live binary triage.
        </div>
      )}

      {error && (
        <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-red-600 text-sm dark:text-red-400">
          <span className="font-semibold">Error:</span> {error}
        </div>
      )}

      {/* Stat ledger */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Card key={stat.label} className="gap-1 py-4">
            <CardHeader className="px-4">
              <CardDescription>{stat.label}</CardDescription>
              <CardTitle className="text-2xl tabular-nums">{stat.value}</CardTitle>
            </CardHeader>
            <CardContent className="px-4 text-muted-foreground text-xs">{stat.detail}</CardContent>
          </Card>
        ))}
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 gap-4 md:gap-6 lg:grid-cols-12">
        {/* Repository + hardware bridge */}
        <div className="space-y-4 md:space-y-6 lg:col-span-4">
          <Card className="gap-0 overflow-hidden p-0">
            <CardHeader className="mb-0 gap-3 border-b p-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm">Repository</CardTitle>
                <Badge variant="outline">{apps.length} pkg</Badge>
              </div>
              <div className="relative">
                <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  className="h-8 pr-7 pl-8 text-xs"
                  aria-label="Search applications"
                  placeholder="Search package or file…"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
                {search && (
                  <button
                    type="button"
                    aria-label="Clear search"
                    onClick={() => setSearch("")}
                    className="absolute top-1/2 right-2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="size-3.5" />
                  </button>
                )}
              </div>
            </CardHeader>
            <CardContent className="max-h-[560px] divide-y divide-border overflow-y-auto">
              {apps
                .filter((app) => `${app.report.package} ${app.filename}`.toLowerCase().includes(search.toLowerCase()))
                .map((app) => {
                  const isSelected = selected?.id === app.id;
                  return (
                    <button
                      type="button"
                      key={app.id}
                      onClick={() => setSelectedID(app.id)}
                      className={cn(
                        "w-full p-4 text-left transition-colors",
                        isSelected ? "bg-muted" : "hover:bg-muted/50",
                      )}
                    >
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="truncate font-semibold text-foreground text-sm">{app.filename}</span>
                        <span className="shrink-0 text-muted-foreground text-xs tabular-nums">
                          {(app.report.size / 1048576).toFixed(1)} MB
                        </span>
                      </div>
                      <span className="mt-1 block truncate font-mono text-muted-foreground text-xs">
                        {app.report.package}
                      </span>
                      <div className="mt-2 flex items-center gap-2 text-[11px] text-muted-foreground">
                        <span>v{app.report.version_name || "—"}</span>
                        <span>·</span>
                        <span>API {app.report.target_sdk}</span>
                        <span>·</span>
                        <span className="tabular-nums">{app.report.findings.length} obs</span>
                      </div>
                    </button>
                  );
                })}

              {!loading && !apps.length && (
                <div className="p-8 text-center text-muted-foreground text-sm">No applications in repository.</div>
              )}
            </CardContent>
          </Card>

          <Card className="gap-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Hardware bridge</CardTitle>
              <Badge variant={onlineDevices.length > 0 ? "secondary" : "outline"}>{onlineDevices.length} online</Badge>
            </div>
            <CardDescription>
              {environment?.message ||
                `${onlineDevices.length} test device(s) ready. Dynamic instrumentation runs on verified ADB targets.`}
            </CardDescription>
            <Button variant="outline" size="sm" className="w-full" asChild>
              <Link href="/android/devices">
                <span>Device lab & tooling</span>
                <ArrowRight className="ml-auto size-3.5" />
              </Link>
            </Button>
          </Card>
        </div>

        {/* Detail */}
        <div className="lg:col-span-8">
          {!selected ? (
            <Card className="min-h-[480px] items-start justify-center">
              <CardTitle className="text-lg">Select or upload an application</CardTitle>
              <CardDescription className="max-w-lg text-sm">
                Upload an Android APK up to 256 MiB to perform offline manifest triage, inspect component exposures,
                and initialize scoped assessments.
              </CardDescription>
              <Button variant="accent" className="mt-2" onClick={() => fileInput.current?.click()}>
                <Upload className="size-3.5" />
                <span>Choose APK file</span>
              </Button>
            </Card>
          ) : (
            <Card className="gap-0 overflow-hidden p-0">
              {/* Selected header */}
              <CardHeader className="mb-0 gap-4 border-b p-6">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 space-y-1">
                    <Badge variant="accent">Verified artifact</Badge>
                    <CardTitle className="break-all font-mono text-base">{selected.report.package}</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => exportReport(selected)}>
                      <Download className="size-3.5" />
                      <span>Export JSON</span>
                    </Button>
                    <Button
                      variant="accent"
                      size="sm"
                      onClick={() => void startAPKTask(selected.id)}
                      disabled={creating}
                    >
                      <Play className="size-3.5" />
                      <span>{creating ? "Starting…" : "Run security assessment"}</span>
                    </Button>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t pt-3 text-muted-foreground text-xs">
                  <span className="font-medium text-foreground">{selected.filename}</span>
                  <span>·</span>
                  <span className="tabular-nums">{(selected.report.size / 1048576).toFixed(2)} MB</span>
                  <span>·</span>
                  <span>Uploaded {new Date(selected.uploaded_at).toLocaleDateString()}</span>
                </div>
              </CardHeader>

              {/* Tabs */}
              <Tabs key={selected.id} defaultValue="overview">
                <div className="border-b px-6 pt-3">
                  <TabsList>
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="triage">Static triage ({selected.report.findings.length})</TabsTrigger>
                    <TabsTrigger value="components">Components ({selected.report.components.length})</TabsTrigger>
                    <TabsTrigger value="permissions">Permissions ({selected.report.permissions.length})</TabsTrigger>
                    <TabsTrigger value="assessments">
                      Assessments ({assessmentTasks.length})
                    </TabsTrigger>
                  </TabsList>
                </div>

                {/* Overview */}
                <TabsContent value="overview" className="space-y-6 p-6">
                  <div className="space-y-2">
                    <span className="font-semibold text-[11px] text-muted-foreground uppercase tracking-wider">
                      Specification
                    </span>
                    <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
                      {[
                        ["Version", `${selected.report.version_name || "—"} (${selected.report.version_code || "—"})`],
                        ["Target SDK", `API ${selected.report.target_sdk}`],
                        ["Minimum SDK", `API ${selected.report.min_sdk}`],
                        ["Bytecode DEX", `${selected.report.dex_files} file(s)`],
                        ["Archive files", `${selected.report.files} entries`],
                        ["Native libs", `${selected.report.native_libraries.length} shared obj`],
                      ].map(([label, value]) => (
                        <div key={label} className="rounded-lg border bg-muted/30 p-3">
                          <span className="block text-[11px] text-muted-foreground uppercase tracking-wider">{label}</span>
                          <span className="mt-1 block font-mono font-semibold text-foreground text-sm tabular-nums">
                            {value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-[11px] text-muted-foreground uppercase tracking-wider">
                        SHA-256 digest
                      </span>
                      <CopyButton text={selected.id} label="Copy hash" size="xs" variant="outline" />
                    </div>
                    <div className="select-all break-all rounded-lg border bg-muted/40 p-3 font-mono text-foreground text-xs">
                      {selected.id}
                    </div>
                  </div>

                  {selected.report.warnings.length > 0 && (
                    <div className="space-y-2">
                      <span className="font-semibold text-[11px] text-muted-foreground uppercase tracking-wider">
                        Analysis notes & coverage caveats
                      </span>
                      <div className="space-y-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4">
                        {selected.report.warnings.map((warning, i) => (
                          <p key={i} className="text-amber-700 text-xs leading-relaxed dark:text-amber-400">
                            • {warning}
                          </p>
                        ))}
                      </div>
                    </div>
                  )}

                  {selected.report.native_libraries.length > 0 && (
                    <div className="space-y-2">
                      <span className="font-semibold text-[11px] text-muted-foreground uppercase tracking-wider">
                        Native shared libraries (.so)
                      </span>
                      <div className="divide-y divide-border rounded-lg border">
                        {selected.report.native_libraries.map((lib) => (
                          <div key={lib} className="p-3 font-mono text-foreground text-xs">
                            {lib}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>

                {/* Static triage */}
                <TabsContent value="triage" className="space-y-5 p-6">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h3 className="font-semibold text-foreground text-sm">Manifest audit findings</h3>
                      <p className="text-muted-foreground text-xs">
                        Static candidate findings flagged by the AndroidManifest parser.
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {["all", "high", "medium", "low", "info"].map((sev) => {
                        const count =
                          sev === "all"
                            ? selected.report.findings.length
                            : selected.report.findings.filter((f) => f.severity.toLowerCase() === sev).length;
                        return (
                          <Button
                            key={sev}
                            size="xs"
                            variant={triageFilter === sev ? "default" : "outline"}
                            onClick={() => setTriageFilter(sev)}
                          >
                            {sev} ({count})
                          </Button>
                        );
                      })}
                    </div>
                  </div>

                  <div className="space-y-3">
                    {filteredFindings.map((finding) => (
                      <div key={finding.id} className="space-y-3 rounded-lg border bg-card p-4">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2.5">
                            <StatusBadge domain="severity" value={finding.severity} dot />
                            <h4 className="font-semibold text-foreground text-sm">{finding.title}</h4>
                          </div>
                          <Badge variant={finding.status === "observed" ? "secondary" : "outline"}>
                            {finding.status === "observed" ? "Observed" : "Needs review"}
                          </Badge>
                        </div>
                        <div className="select-all break-all rounded-lg border bg-muted/40 p-3 font-mono text-foreground text-xs">
                          {finding.evidence}
                        </div>
                        <div className="border-t pt-2 text-muted-foreground text-xs leading-relaxed">
                          <span className="font-semibold text-foreground">Remediation: </span>
                          {finding.recommendation}
                        </div>
                      </div>
                    ))}

                    {!filteredFindings.length && (
                      <div className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
                        No findings match the selected criteria.
                      </div>
                    )}
                  </div>
                </TabsContent>

                {/* Components */}
                <TabsContent value="components" className="space-y-5 p-6">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h3 className="font-semibold text-foreground text-sm">Declared IPC components</h3>
                      <p className="text-muted-foreground text-xs">
                        Exported entrypoints reachable by external applications or system intents.
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Input
                        className="h-8 w-48 text-xs"
                        placeholder="Filter components…"
                        value={componentSearch}
                        onChange={(e) => setComponentSearch(e.target.value)}
                      />
                      <div className="flex flex-wrap gap-1.5">
                        {["all", "activity", "service", "receiver", "provider"].map((k) => (
                          <Button
                            key={k}
                            size="xs"
                            variant={componentFilter === k ? "default" : "outline"}
                            onClick={() => setComponentFilter(k)}
                          >
                            {k}
                          </Button>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[50%]">Component & kind</TableHead>
                          <TableHead className="w-[20%]">Export status</TableHead>
                          <TableHead className="w-[30%]">Guarding permission</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredComponents.map((component) => {
                          const isExported = component.exported === "true";
                          const hasPermission = Boolean(component.permission);
                          return (
                            <TableRow key={`${component.kind}:${component.name}`}>
                              <TableCell className="font-mono text-xs">
                                <span className="font-semibold text-foreground">{component.name}</span>
                                <span className="mt-0.5 block text-[11px] text-muted-foreground uppercase tracking-wider">
                                  {component.kind}
                                </span>
                              </TableCell>
                              <TableCell>
                                {isExported && !hasPermission ? (
                                  <Badge variant="destructive">Public</Badge>
                                ) : isExported && hasPermission ? (
                                  <Badge variant="outline">Guarded</Badge>
                                ) : (
                                  <Badge variant="ghost">Internal</Badge>
                                )}
                              </TableCell>
                              <TableCell className="font-mono text-xs">
                                {component.permission ? (
                                  <span className="text-foreground">{component.permission}</span>
                                ) : isExported ? (
                                  <span className="text-[#E30613]">None specified</span>
                                ) : (
                                  <span className="text-muted-foreground">—</span>
                                )}
                              </TableCell>
                            </TableRow>
                          );
                        })}

                        {!filteredComponents.length && (
                          <TableRow>
                            <TableCell colSpan={3} className="p-8 text-center text-muted-foreground text-sm">
                              No components match the filter.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </TabsContent>

                {/* Permissions */}
                <TabsContent value="permissions" className="space-y-5 p-6">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h3 className="font-semibold text-foreground text-sm">Requested permissions</h3>
                      <p className="text-muted-foreground text-xs">
                        Android runtime and install-time permission assertions.
                      </p>
                    </div>
                    <Input
                      className="h-8 w-60 text-xs"
                      placeholder="Search permissions…"
                      value={permissionSearch}
                      onChange={(e) => setPermissionSearch(e.target.value)}
                    />
                  </div>

                  <div className="divide-y divide-border rounded-lg border">
                    {filteredPermissions.map((permission) => {
                      const isDangerous = DANGEROUS_PERMISSIONS.has(permission);
                      return (
                        <div key={permission} className="flex items-center justify-between gap-4 p-3 transition-colors hover:bg-muted/40">
                          <div className="min-w-0 space-y-1">
                            <span className="block select-all truncate font-medium font-mono text-foreground text-xs">
                              {permission}
                            </span>
                            {isDangerous ? (
                              <Badge variant="accent">Dangerous / sensitive</Badge>
                            ) : (
                              <Badge variant="ghost">Normal / install-time</Badge>
                            )}
                          </div>
                          <CopyButton text={permission} label="Copy" size="xs" variant="outline" />
                        </div>
                      );
                    })}

                    {!filteredPermissions.length && (
                      <div className="p-8 text-center text-muted-foreground text-sm">No permissions found.</div>
                    )}
                  </div>
                </TabsContent>

                {/* Assessments */}
                <TabsContent value="assessments" className="space-y-5 p-6">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h3 className="font-semibold text-foreground text-sm">Linked assessments</h3>
                      <p className="text-muted-foreground text-xs">
                        Formal security evaluations and audit execution records.
                      </p>
                    </div>
                    <Button
                      variant="accent"
                      size="sm"
                      onClick={() => void startAPKTask(selected.id)}
                      disabled={creating}
                    >
                      <Play className="size-3.5" />
                      <span>{creating ? "Starting…" : "Run security assessment"}</span>
                    </Button>
                  </div>

                  {tasksError && (
                    <p role="alert" className="text-[#E30613] text-xs">
                      {tasksError}
                    </p>
                  )}

                  <div className="divide-y divide-border rounded-lg border">
                    {assessmentTasks.map((task) => (
                      <Link
                        key={task.id}
                        href={`/function/tasks/detail?id=${encodeURIComponent(task.id)}`}
                        className="flex items-center justify-between gap-3 p-4 transition-colors hover:bg-muted/40"
                      >
                        <div className="min-w-0">
                          <span className="block truncate font-semibold text-foreground text-sm">{task.name || task.id}</span>
                          <span className="mt-0.5 block text-[11px] text-muted-foreground uppercase tracking-wider">
                            Legacy task session
                          </span>
                        </div>
                        <StatusBadge domain="task" value={task.status} dot />
                      </Link>
                    ))}

                    {!tasksError && !assessmentTasks.length && (
                      <div className="p-12 text-center text-muted-foreground text-sm">
                        No assessments linked to this artifact yet.
                      </div>
                    )}
                  </div>
                </TabsContent>
              </Tabs>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
