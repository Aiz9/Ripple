"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowDownIcon, ArrowUpIcon, ArrowUpRightIcon, ChevronRightIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { api } from "@/lib/api";
import { useStoredSortPreference } from "@/lib/sort-preference";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus } from "@/lib/types";
import { cn, visibleInterval } from "@/lib/utils";

type FindingSortField = "time";

const FINDING_SORT_FIELDS: readonly FindingSortField[] = ["time"];
const FINDING_SORT_PREFERENCE_KEY = "artex_task_findings_sort";

function findingLabel(finding: Finding): string {
  if (finding.name?.trim()) return finding.name;
  if (finding.vulnclass?.trim()) return finding.vulnclass;
  return "Uncategorized";
}

const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function Row({
  f,
  contextTaskId,
  selected,
  onToggleSelect,
  onStatus,
  onDelete,
}: {
  f: Finding;
  contextTaskId: string;
  selected: boolean;
  onToggleSelect: (f: Finding) => void;
  onStatus: (f: Finding, next: FindingStatus) => void;
  onDelete: (f: Finding) => void;
}) {
  const [open, setOpen] = React.useState(false);
  const selectable = Boolean(f.finding_id) && !f.inherited;
  return (
    <div className={cn("border-b last:border-b-0", selected && "bg-accent/30")}>
      <div className="flex w-full items-center gap-3 px-4 py-3 text-sm hover:bg-accent/40">
        {selectable ? (
          <Checkbox
            checked={selected}
            onCheckedChange={() => onToggleSelect(f)}
            aria-label="Select finding"
            className="shrink-0"
          />
        ) : (
          <span className="size-4 shrink-0" />
        )}
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex min-w-0 flex-1 items-center gap-3 text-left"
        >
          <ChevronRightIcon
            className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
          />
          <StatusBadge domain="severity" value={f.severity} dot />
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate font-medium">{findingLabel(f)}</span>
              {f.inherited && f.source_task_id && (
                <Badge variant="outline" className="shrink-0">
                  Source #{f.source_task_id} · Read only
                </Badge>
              )}
            </div>
            <span className="truncate text-xs text-muted-foreground">{f.summary}</span>
          </div>
        </button>
        <Badge variant="outline">Traffic evidence {f.traffic_count ?? 0}  records</Badge>
        {f.assets && f.assets.length > 0 && (
          <div className="hidden shrink-0 flex-wrap justify-end gap-1 sm:flex">
            {f.assets.slice(0, 2).map((a) => (
              <code
                key={a.id}
                className="max-w-[10rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                title={`${a.type} · ${a.label}`}
              >
                {a.label}
              </code>
            ))}
            {f.assets.length > 2 && <span className="text-xs text-muted-foreground">+{f.assets.length - 2}</span>}
          </div>
        )}
        {f.finding_id && !f.inherited ? (
          <Select value={f.status} onValueChange={(v) => onStatus(f, v as FindingStatus)}>
            <SelectTrigger size="sm" className="h-7 w-28 shrink-0 border-none px-1 shadow-none focus-visible:ring-0">
              <StatusBadge domain="finding" value={f.status} dot />
            </SelectTrigger>
            <SelectContent position="popper" align="end">
              <SelectGroup>
                {FINDING_STATUSES.map((st) => (
                  <SelectItem key={st} value={st}>
                    {statusMeta("finding", st).label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        ) : (
          <StatusBadge domain="finding" value={f.status} dot />
        )}
        <span className="hidden shrink-0 text-xs text-muted-foreground md:block">
          {new Date(f.ts).toLocaleString("en-US")}
        </span>
        {f.finding_id && (
          <Link
            href={
              f.inherited
                ? `/function/findings/detail?id=${f.finding_id}&context_task=${contextTaskId}`
                : `/function/findings/detail?id=${f.finding_id}`
            }
            className="text-muted-foreground hover:text-primary inline-flex shrink-0 items-center gap-0.5 text-xs"
            title="View finding details"
          >
            Details
            <ArrowUpRightIcon className="size-3" />
          </Link>
        )}
        {f.finding_id && !f.inherited && (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                size="icon"
                variant="ghost"
                className="size-7 shrink-0 text-muted-foreground hover:text-destructive"
                aria-label="Delete finding"
              >
                <Trash2Icon className="size-4" />
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete this finding?</AlertDialogTitle>
                <AlertDialogDescription className="break-words">
                  “<span className="break-all">{findingLabel(f)}</span>” will be permanently deleted from findings,
                  task findings, and the exploration graph. This action cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => onDelete(f)}>Delete</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}
      </div>
      {open && (
        <div className="bg-muted/30 px-4 pb-4 pl-11">
          <div className="mb-1 text-xs font-medium text-muted-foreground">Evidence / PoC</div>
          <pre className="overflow-auto rounded-md border bg-background p-3 font-mono text-xs whitespace-pre-wrap">
            {f.evidence}
          </pre>
        </div>
      )}
    </div>
  );
}

export function FindingsTab({ taskId }: { taskId: string }) {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [sortPreference, setSortPreference] = useStoredSortPreference(
    FINDING_SORT_PREFERENCE_KEY,
    FINDING_SORT_FIELDS,
    "time",
    "desc",
  );

  React.useEffect(() => {
    let active = true;
    const load = () => {
      api
        .findings(taskId)
        .then((fs) => {
          if (active) setFindings(fs);
        })
        .catch(() => {
          // Keep the last successful snapshot during transient refresh failures.
        });
    };
    load();
    const t = visibleInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [taskId]);

  const onStatus = React.useCallback(async (f: Finding, next: FindingStatus) => {
    if (f.inherited || !f.finding_id || next === f.status) return;
    const prev = f.status;
    setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: next } : x)));
    try {
      await api.setFindingStatus(f.finding_id, next);
      toast.success(`Marked as “${statusMeta("finding", next).label}”`);
    } catch (e) {
      setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: prev } : x)));
      toast.error("Update failed: " + (e as Error).message);
    }
  }, []);

  const onDelete = React.useCallback(async (f: Finding) => {
    if (f.inherited || !f.finding_id) return;
    try {
      await api.deleteFinding(f.finding_id);
      setFindings((cur) => cur.filter((x) => x.id !== f.id));
      setSelected((cur) => {
        if (!cur.has(f.id)) return cur;
        const next = new Set(cur);
        next.delete(f.id);
        return next;
      });
      toast.success("Finding deleted");
    } catch (e) {
      toast.error("Delete failed: " + (e as Error).message);
    }
  }, []);

  // Multi-select + bulk delete. Selection is keyed by the row's stable id.
  const [selected, setSelected] = React.useState<Set<string>>(() => new Set());
  const toggleSelect = React.useCallback((f: Finding) => {
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(f.id)) next.delete(f.id);
      else next.add(f.id);
      return next;
    });
  }, []);
  const bulkDelete = React.useCallback(async () => {
    const chosen = findings.filter((f) => selected.has(f.id) && f.finding_id && !f.inherited);
    const ids = chosen.map((f) => f.finding_id as string);
    if (ids.length === 0) return;
    try {
      const res = await api.deleteFindings(ids);
      const removed = new Set(chosen.map((f) => f.id));
      setFindings((cur) => cur.filter((x) => !removed.has(x.id)));
      setSelected(new Set());
      toast.success(`Deleted ${res.deleted} finding${res.deleted === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error("Bulk delete failed: " + (e as Error).message);
    }
  }, [findings, selected]);

  const items = findings
    .filter((f) => f.task_id === taskId || f.inherited)
    .sort((a, b) => {
      const compared = Date.parse(a.ts) - Date.parse(b.ts);
      if (compared !== 0) return sortPreference.direction === "asc" ? compared : -compared;
      return b.id.localeCompare(a.id, undefined, { numeric: true });
    });

  const selectableItems = items.filter((f) => f.finding_id && !f.inherited);
  const selectedCount = selectableItems.filter((f) => selected.has(f.id)).length;
  const allSelected = selectableItems.length > 0 && selectedCount === selectableItems.length;

  return (
    <Card className="overflow-hidden py-0">
      <CardContent className="px-0">
        <div className="flex items-center gap-3 border-b px-4 py-2 text-xs text-muted-foreground">
          {selectableItems.length > 0 ? (
            <Checkbox
              checked={allSelected}
              onCheckedChange={() => setSelected(allSelected ? new Set() : new Set(selectableItems.map((f) => f.id)))}
              aria-label="Select all findings"
              className="shrink-0"
            />
          ) : (
            <span className="size-4 shrink-0" />
          )}
          {selectedCount > 0 ? (
            <div className="flex min-w-0 flex-1 items-center gap-2">
              <span className="text-foreground tabular-nums">{selectedCount} selected</span>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button size="sm" variant="destructive" className="h-7">
                    <Trash2Icon className="size-3.5" data-icon="inline-start" />
                    Delete selected
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>
                      Delete {selectedCount} finding{selectedCount === 1 ? "" : "s"}?
                    </AlertDialogTitle>
                    <AlertDialogDescription>
                      The selected findings will be permanently deleted from findings, task findings, and the exploration
                      graph. This action cannot be undone.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction onClick={bulkDelete}>Delete {selectedCount}</AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
              <Button size="sm" variant="ghost" className="h-7" onClick={() => setSelected(new Set())}>
                Clear
              </Button>
            </div>
          ) : (
            <span className="min-w-0 flex-1">Vulnerability</span>
          )}
          <button
            type="button"
            className="inline-flex items-center gap-1 outline-none focus-visible:underline"
            aria-label={`Discovery time: ${sortPreference.direction === "asc" ? "ascending" : "descending"}; click to reverse sort order`}
            onClick={() =>
              setSortPreference((current) => ({
                field: "time",
                direction: current.direction === "asc" ? "desc" : "asc",
              }))
            }
          >
            <span>Discovered at</span>
            {sortPreference.direction === "asc" ? (
              <ArrowUpIcon className="size-3.5" />
            ) : (
              <ArrowDownIcon className="size-3.5" />
            )}
          </button>
        </div>
        {items.map((f) => (
          <Row
            key={f.id}
            f={f}
            contextTaskId={taskId}
            selected={selected.has(f.id)}
            onToggleSelect={toggleSelect}
            onStatus={onStatus}
            onDelete={onDelete}
          />
        ))}
        {items.length === 0 && (
          <p className="px-4 py-8 text-center text-sm text-muted-foreground">No confirmed findings for this task or its directly related tasks.</p>
        )}
      </CardContent>
    </Card>
  );
}
