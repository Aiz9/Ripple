import { http } from "@/lib/api";
import { MOCK } from "@/lib/mock/enabled";
import type { Task } from "@/lib/types";

export interface AndroidFinding {
  id: string;
  title: string;
  severity: string;
  evidence: string;
  recommendation: string;
  status: "observed" | "review";
}

export interface AndroidApp {
  id: string;
  filename: string;
  uploaded_at: string;
  apk_path: string;
  report_path: string;
  report: {
    package: string;
    version_name: string;
    version_code: string;
    min_sdk: string;
    target_sdk: string;
    sha256: string;
    size: number;
    files: number;
    dex_files: number;
    native_libraries: string[];
    permissions: string[];
    components: { kind: string; name: string; exported: string; permission: string }[];
    findings: AndroidFinding[];
    warnings: string[];
  };
}

export interface AndroidEnvironment {
  tools: Record<string, boolean>;
  devices: { serial: string; state: string; model: string }[];
  message: string;
  max_upload_bytes: number;
}

export const androidAPI = {
  apps: () => http<{ apps: AndroidApp[] }>("/android/apps").then((r) => r.apps),
  environment: () => http<AndroidEnvironment>("/android/environment"),
  upload: async (file: File) => {
    if (MOCK) throw new Error("Demo mode cannot analyze APKs. Start the Android backend to upload an application.");
    const body = new FormData();
    body.append("file", file);
    return http<AndroidApp>("/android/apps", { method: "POST", body });
  },
  // createTask runs an uploaded APK through the SAME web task pipeline as a web
  // target (goals → planner → worker agents → Current tasks), seeding a MASVS
  // audit objective against the local APK. Returns the created task.
  createTask: (input: {
    apkId: string;
    name?: string;
    description?: string;
    goal?: string;
    scopeHosts?: string[];
    llmProfileIds?: number[];
    timeoutSeconds?: number;
  }) => {
    if (MOCK) return Promise.reject<Task>(new Error("Start the Android backend to create APK tasks."));
    return http<Task>("/tasks/apk", {
      method: "POST",
      body: JSON.stringify({
        apk_id: input.apkId,
        name: input.name ?? "",
        description: input.description ?? "",
        goal: input.goal ?? "",
        scope_hosts: input.scopeHosts ?? [],
        llm_profile_ids: input.llmProfileIds ?? [],
        timeout_seconds: input.timeoutSeconds ?? 0,
      }),
    });
  },

  // apkTaskTemplate returns the default MASVS description + goal for an uploaded APK,
  // so the dialog can pre-fill them as editable text instead of the server generating
  // them at create time.
  apkTaskTemplate: (apkId: string) => {
    if (MOCK) return Promise.reject<{ description: string; goal: string }>(new Error("Start the Android backend."));
    return http<{ description: string; goal: string }>(`/tasks/apk/template?apk_id=${encodeURIComponent(apkId)}`);
  },
};
