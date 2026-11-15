import type { AndroidApp, AndroidEnvironment } from "@/lib/android-api";

const id = "a71d90e34f2b6078c9d158af302b4e690817ac56de4f230a9b6c81d7e05f3294";

export const demoAndroidApps: AndroidApp[] = [
  {
    id,
    filename: "atlas-wallet-demo.apk",
    uploaded_at: "2026-10-20T08:30:00Z",
    apk_path: `/demo/android/apps/${id}/app.apk`,
    report_path: `/demo/android/apps/${id}/report.json`,
    report: {
      package: "com.example.atlaswallet",
      version_name: "2.4.1",
      version_code: "241",
      min_sdk: "26",
      target_sdk: "35",
      sha256: id,
      size: 18350080,
      files: 1248,
      dex_files: 3,
      native_libraries: ["lib/arm64-v8a/libwallet.so"],
      permissions: ["android.permission.CAMERA", "android.permission.INTERNET", "android.permission.USE_BIOMETRIC"],
      components: [
        { kind: "activity", name: "com.example.atlaswallet.MainActivity", exported: "true", permission: "" },
        { kind: "activity", name: "com.example.atlaswallet.TransferActivity", exported: "true", permission: "" },
        { kind: "provider", name: "com.example.atlaswallet.FileProvider", exported: "false", permission: "" },
      ],
      findings: [
        {
          id: "debuggable",
          title: "Debugging enabled",
          severity: "high",
          evidence: "Simulated AndroidManifest.xml: application android:debuggable=true",
          recommendation: "Disable debugging in release builds; verify the installed build.",
          status: "observed",
        },
        {
          id: "cleartext",
          title: "Cleartext traffic allowed by manifest",
          severity: "medium",
          evidence: "Simulated AndroidManifest.xml: application android:usesCleartextTraffic=true",
          recommendation:
            "Inspect network security configuration and actual requests; enforce TLS for sensitive traffic.",
          status: "review",
        },
        {
          id: "exported-2",
          title: "Review exported activity: TransferActivity",
          severity: "info",
          evidence: "Simulated AndroidManifest.xml: activity exported=true; permission unspecified",
          recommendation: "Confirm intended exposure and validate authorization and input handling.",
          status: "review",
        },
      ],
      warnings: [
        "Simulated demo data. No APK has been uploaded or tested. Runtime security, code, resource values, and signing have not been verified.",
      ],
    },
  },
];

export const demoAndroidEnvironment: AndroidEnvironment = {
  tools: { adb: false, apktool: false, jadx: false, apksigner: false, frida: false, objection: false },
  devices: [],
  message: "Demo mode: device and tool discovery is unavailable. Connect the backend to inspect your test environment.",
  max_upload_bytes: 256 * 1024 * 1024,
};
