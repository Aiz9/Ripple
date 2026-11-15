"use client";

import * as React from "react";

import { SmartphoneIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { TaskTemplateControls } from "@/components/task-template-controls";
import { androidAPI, type AndroidApp } from "@/lib/android-api";

// ApkTaskDialog runs an uploaded APK through the SAME web task pipeline as a web
// target: it POSTs to /api/tasks/apk, which seeds a MASVS audit objective against
// the local APK and launches the standard goals → planner → worker agents. The
// resulting task appears in the Current tasks list like any web task.
export function ApkTaskDialog({ onCreated }: { onCreated?: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [apps, setApps] = React.useState<AndroidApp[]>([]);
  const [apkId, setApkId] = React.useState("");
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [goal, setGoal] = React.useState("");
  const [templateID, setTemplateID] = React.useState<number | null>(null);
  const [busy, setBusy] = React.useState(false);
  const contentRef = React.useRef<HTMLDivElement>(null);

  const load = React.useCallback(async () => {
    try {
      setApps(await androidAPI.apps());
    } catch {
      // Android backend may be off; the dialog still allows upload.
    }
  }, []);

  React.useEffect(() => {
    if (open) void load();
  }, [open, load]);

  // Pre-fill the editable description + goal with the server's default MASVS template
  // for the selected APK. The operator then owns both fields; what they submit is used
  // verbatim. Re-selecting an APK reloads the defaults (overwriting prior edits).
  React.useEffect(() => {
    if (!apkId) return;
    let cancelled = false;
    void androidAPI
      .apkTaskTemplate(apkId)
      .then((t) => {
        if (cancelled) return;
        setDescription(t.description);
        setGoal(t.goal);
      })
      .catch(() => {
        // Backend off or APK missing: leave fields as-is; the server still fills blanks.
      });
    return () => {
      cancelled = true;
    };
  }, [apkId]);

  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setBusy(true);
    try {
      const app = await androidAPI.upload(file);
      await load();
      setApkId(app.id);
      toast.success(`Uploaded ${app.filename} (${app.report?.package ?? "unknown package"})`);
    } catch (err) {
      toast.error("Upload failed: " + (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const create = async () => {
    if (!apkId) {
      toast.error("Select or upload an APK first");
      return;
    }
    setBusy(true);
    try {
      await androidAPI.createTask({ apkId, name: name.trim(), description: description.trim(), goal: goal.trim() });
      toast.success("APK task created — watch it under Current tasks");
      setOpen(false);
      setApkId("");
      setName("");
      setDescription("");
      setGoal("");
      setTemplateID(null);
      onCreated?.();
    } catch (err) {
      toast.error("Create failed: " + (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <SmartphoneIcon data-icon="inline-start" />
          New APK task
        </Button>
      </DialogTrigger>
      <DialogContent ref={contentRef} aria-busy={busy}>
        <DialogHeader>
          <DialogTitle>New APK task</DialogTitle>
          <DialogDescription>
            Run an uploaded APK through the same agent pipeline as a web target — a MASVS v2 audit by the
            goals → planner → worker agents. It appears in Current tasks like any task.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <TaskTemplateControls
            description={description}
            goal={goal}
            selectedTemplateID={templateID}
            onSelectedTemplateIDChange={setTemplateID}
            onApply={(template) => {
              setDescription((template.description ?? "").trim());
              setGoal((template.goal ?? "").trim());
            }}
            portalContainer={contentRef}
          />
          <div className="space-y-1.5">
            <Label htmlFor="apk-select">APK</Label>
            <Select value={apkId} onValueChange={setApkId}>
              <SelectTrigger id="apk-select">
                <SelectValue placeholder="Select an uploaded APK" />
              </SelectTrigger>
              <SelectContent>
                {apps.map((a) => (
                  <SelectItem key={a.id} value={a.id}>
                    {a.filename} — {a.report?.package ?? a.id.slice(0, 12)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input type="file" accept=".apk" onChange={onUpload} disabled={busy} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="apk-task-name">Task name (optional)</Label>
            <Input
              id="apk-task-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="APK: com.example.app"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="apk-task-goal">Goal</Label>
            <Textarea
              id="apk-task-goal"
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              placeholder="Select an APK to pre-fill the default MASVS goal, then edit."
              rows={3}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="apk-task-description">Description</Label>
            <Textarea
              id="apk-task-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Select an APK to pre-fill the default MASVS workflow, then edit."
              rows={10}
            />
          </div>
        </div>
        <DialogFooter>
          <Button onClick={create} disabled={busy || !apkId}>
            Create task
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
