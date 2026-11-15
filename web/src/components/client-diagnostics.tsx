"use client";
import { useEffect } from "react";
import { toast } from "sonner";
import { flushClientDiagnostics, reportClientError } from "@/lib/client-diagnostics";

export function ClientDiagnostics() {
  useEffect(() => {
    const onError = (event: ErrorEvent) => reportClientError("browser", event.message || "Browser error", event.error);
    const onRejection = (event: PromiseRejectionEvent) => reportClientError("unhandledrejection", event.reason instanceof Error ? event.reason.message : String(event.reason), event.reason);
    const originalConsole = console.error;
    const originalToast = toast.error;
    console.error = (...args: unknown[]) => {
      const message = args.map((arg) => arg instanceof Error ? arg.message : typeof arg === "string" ? arg : "[non-text diagnostic argument]").join(" ");
      reportClientError("console", message, args.find((arg) => arg instanceof Error));
      originalConsole.apply(console, args);
    };
    toast.error = (...args: Parameters<typeof toast.error>) => {
      reportClientError("console", `UI error: ${typeof args[0] === "string" ? args[0] : "Error notification"}`);
      return originalToast(...args);
    };
    window.addEventListener("error", onError);
    window.addEventListener("unhandledrejection", onRejection);
    window.addEventListener("online", flushClientDiagnostics);
    const timer = setInterval(flushClientDiagnostics, 10000);
    void flushClientDiagnostics();
    return () => {
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onRejection);
      window.removeEventListener("online", flushClientDiagnostics);
      clearInterval(timer);
      console.error = originalConsole;
      toast.error = originalToast;
    };
  }, []);
  return null;
}
