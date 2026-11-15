export type FindingTestType = "static" | "dynamic" | null;

// shortcut: findings carry no structured test-type field, so this infers it from the
// evidence text the agent writes; persist a field at record time if this misclassifies.
const DYNAMIC = /\b(curl|frida|objection|burp|adb shell|logcat|runtime|live|intercept\w*|HTTP\/[12]|proxy)\b/i;
const STATIC = /\b(static|jadx|apktool|aapt|decompil\w*|smali|manifest|mobsf|semgrep|osv)\b/i;

export function findingTestType(evidence: string | undefined, trafficCount = 0): FindingTestType {
  const text = evidence ?? "";
  // The agent leads static findings with "Static (...)" even when it mentions logcat etc.
  if (/^\s*static\b/i.test(text)) return "static";
  if (trafficCount > 0 || DYNAMIC.test(text)) return "dynamic";
  if (STATIC.test(text)) return "static";
  return null;
}
