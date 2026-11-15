"use client";

// Shared pieces of the LLM retry config: "count + interval" for each of the five retry layers.
//
// The five layers from inside out: connect (SDK) -> empty response (SDK) -> same-provider safe window -> rotation circuit breaker -> intent rerun.
// The first three follow the endpoint, so each model config can override the global defaults; the last two are process-level with a single global copy.
//
// Every input follows the same "empty = not configured" semantics as the backend db.RetryRule:
//   count      empty/0 = built-in default | -1 = disable this retry layer | >0 = use this count
//   interval   empty/0 = this layer's original exponential backoff | >0 = use this fixed interval in milliseconds

import * as React from "react";

import { Loader2Icon, SaveIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { LLMRetryOverride, LLMRetryPolicy, LLMRetryRule } from "@/lib/types";

export const ZERO_RULE: LLMRetryRule = { attempts: 0, interval_ms: 0 };
export const ZERO_OVERRIDE: LLMRetryOverride = {
  connect: ZERO_RULE,
  empty: ZERO_RULE,
  stream: ZERO_RULE,
};
const ZERO_POLICY: LLMRetryPolicy = {
  ...ZERO_OVERRIDE,
  breaker: ZERO_RULE,
  intent: ZERO_RULE,
};

type LayerMeta = {
  title: string;
  /** Where this retry layer happens and who performs it */
  where: string;
  /** Which errors reach this layer -- down to status codes, so nobody has to guess */
  trigger: string;
  /** Errors that look similar but do NOT go through this layer, so a setting with no visible effect is not mistaken for a bug */
  skips?: string;
  desc: string;
  attemptsLabel: string;
  /** Default when the count is left empty, used as the placeholder */
  defAttempts: number;
  /** Default policy when the interval is left empty, used as the placeholder */
  defInterval: string;
  /** What a count of -1 means */
  offHint: string;
};

export const RETRY_LAYERS = {
  connect: {
    title: "Connection retries",
    where: "SDK · Before HTTP 200",
    trigger:
      "Connection failures before HTTP 200: resets, read/write timeouts, DNS errors, and HTTP 408, 429, 500, 502, 503, or 504.",
    skips: "Other status codes (400 / 401 / 403 / 404 / 413 / 422, etc.) are deterministic rejections and are returned immediately without retrying.",
    desc: "Resends the same request. Once streaming begins (HTTP 200 received), interruptions are handled by another layer.",
    attemptsLabel: "Retry count",
    defAttempts: 3,
    defInterval: "0.5s → 1s → 2s exponential backoff (maximum 8s)",
    offHint: "-1 = no retries; return errors immediately",
  },
  empty: {
    title: "Empty response retries",
    where: "SDK · OpenAI format only",
    trigger:
      "HTTP 200 and normal stop finish_reason, but no content blocks at all. This can occur with empty gateway frames, missing reasoning fields, or sampling issues.",
    skips: "Empty content caused by max_tokens truncation is excluded. Increase the output limit instead; retrying would hit the same limit.",
    desc: "Resends the entire prompt, which is costly for long contexts. Keep the retry count low.",
    attemptsLabel: "Retry count",
    defAttempts: 2,
    defInterval: "0.5s → 1s → 2s exponential backoff (maximum 8s)",
    offHint: "-1 = return empty responses directly",
  },
  stream: {
    title: "Same-provider safe-window retries",
    where: "Application · Before any output is delivered",
    trigger:
      "After HTTP 200, the stream disconnects or reports overload, 429, or 5xx, before any token has been delivered to the caller.",
    skips:
      "No retries for exhausted quota (402 / insufficient_quota; handled by failover), context overflow (413 / context length; handled by compaction), or deterministic 400 / 401 / 403 / 404 / 422 rejections.",
    desc: "Replays the same request on the same profile. Since no output has been delivered, replay does not duplicate model output or tool execution.",
    attemptsLabel: "Retry count",
    defAttempts: 2,
    defInterval: "0.5s → 1s exponential backoff (maximum 4s)",
    offHint: "-1 = pass stream failures to outer intent retries",
  },
  breaker: {
    title: "Failover circuit breaker",
    where: "Application · Shared across the process",
    trigger:
      "Trips after consecutive transient failures (429, 5xx, network errors) reach the threshold. Deterministic failures such as insufficient funds (402), invalid keys (401 / 403), or missing models (404) trip immediately.",
    skips: "One successful call resets the counter, so occasional failures do not accumulate indefinitely.",
    desc: "A tripped profile enters cooldown and is skipped by failover. State persists across restarts.",
    attemptsLabel: "Consecutive failures before tripping",
    defAttempts: 3,
    defInterval: "1min → 5min → 30min cooldown steps",
    offHint: "-1 = never trip on transient failures (deterministic failures still trip)",
  },
  intent: {
    title: "Intent retries",
    where: "Application · Shared across the process",
    trigger:
      "When inner layers cannot recover, the worker ends with model_error. This includes exhausted retries or a stream failure after output delivery, when replay is unsafe and the intent must restart.",
    skips: "Quota exhaustion is handled by profile failover, without intent retries. Pausing, termination, or wrap-up interrupts backoff immediately.",
    desc: "Restarts the entire intent. As the outermost layer, each retry repeats the inner retry allowances.",
    attemptsLabel: "Intent retry count",
    defAttempts: 2,
    defInterval: "Fixed 3s",
    offHint: "-1 = no retry; mark the intent blocked",
  },
} satisfies Record<string, LayerMeta>;

type LayerKey = keyof typeof RETRY_LAYERS;

/** Human-readable milliseconds, shown only next to the input so nobody has to count zeros. */
function humanMs(ms: number) {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${Number((ms / 1000).toFixed(2))}s`;
  return `${Number((ms / 60_000).toFixed(2))}min`;
}

/** Controlled number input: empty string <-> 0; intermediate states ("-", "1e") stay local and do not bother the parent. */
function NumField({
  id,
  value,
  onChange,
  placeholder,
  min,
}: {
  id: string;
  value: number;
  onChange: (n: number) => void;
  placeholder: string;
  min: number;
}) {
  const [text, setText] = React.useState(value === 0 ? "" : String(value));
  // Follow along when the parent swaps in a whole new set of values (policy loaded, config switched); typing never reaches here,
  // because then value already equals the parsed local text.
  React.useEffect(() => {
    const incoming = value === 0 ? "" : String(value);
    setText((cur) => (Number(cur || 0) === value ? cur : incoming));
  }, [value]);
  return (
    <Input
      id={id}
      type="number"
      min={min}
      className="w-28 shrink-0"
      value={text}
      placeholder={placeholder}
      onChange={(e) => {
        setText(e.target.value);
        const n = Number(e.target.value);
        onChange(e.target.value.trim() === "" || !Number.isFinite(n) ? 0 : Math.trunc(n));
      }}
    />
  );
}

/** The two knobs of one retry layer. idPrefix keeps each label's htmlFor unique when the layer appears several times on a page. */
export function RetryRuleFields({
  layer,
  idPrefix,
  value,
  onChange,
  compact,
}: {
  layer: LayerKey;
  idPrefix: string;
  value: LLMRetryRule;
  onChange: (r: LLMRetryRule) => void;
  /** true = compact version in the config drawer: drop the expanded explanation and keep only the "which errors reach this layer" line */
  compact?: boolean;
}) {
  const meta = RETRY_LAYERS[layer];
  const human = humanMs(value.interval_ms);
  return (
    <div className={compact ? "grid gap-2" : "grid gap-3 rounded-lg border p-3"}>
      <div className="grid gap-0.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <Label className="text-sm">{meta.title}</Label>
          <span className="text-muted-foreground text-xs">{meta.where}</span>
        </div>
        {/* Which errors reach this layer, down to status codes -- when a knob has no visible effect, the error usually never lands in this layer. */}
        <p className="text-muted-foreground text-xs">
          <span className="font-medium text-foreground">Trigger</span>: {meta.trigger}
        </p>
        {!compact && meta.skips && (
          <p className="text-muted-foreground text-xs">
            <span className="font-medium text-foreground">Excluded</span>: {meta.skips}
          </p>
        )}
        {!compact && <p className="text-muted-foreground text-xs">{meta.desc}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-n`} className="text-muted-foreground text-xs">
            {meta.attemptsLabel}
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-n`}
            min={-1}
            value={value.attempts}
            placeholder={`Default ${meta.defAttempts}`}
            onChange={(n) => onChange({ ...value, attempts: n })}
          />
        </div>
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-ms`} className="text-muted-foreground text-xs">
            Interval (ms)
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-ms`}
            min={0}
            value={value.interval_ms}
            placeholder="Default backoff"
            onChange={(n) => onChange({ ...value, interval_ms: n })}
          />
          <span className="text-muted-foreground text-xs">{human ? `Fixed ${human}` : meta.defInterval}</span>
        </div>
      </div>
      {!compact && <p className="text-muted-foreground text-xs">Leave blank for default; {meta.offHint}.</p>}
    </div>
  );
}

/** The three overridable layers in the model config drawer (the three that follow the endpoint). */
export function ProfileRetryFields({
  value,
  onChange,
}: {
  value: LLMRetryOverride;
  onChange: (o: LLMRetryOverride) => void;
}) {
  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="grid gap-0.5">
        <Label className="text-sm">Retry overrides</Label>
        <p className="text-muted-foreground text-xs">
          Applies only to this profile, overriding global “Retries and backoff” settings. Blank fields inherit global values; -1 disables a retry layer. An interval replaces exponential backoff with a fixed delay. Circuit breaking and intent retries are process-wide and configured globally.
        </p>
      </div>
      {(["connect", "empty", "stream"] as const).map((k) => (
        <div key={k} className="border-t pt-3 first:border-t-0 first:pt-0">
          <RetryRuleFields
            compact
            layer={k}
            idPrefix="pf"
            value={value[k]}
            onChange={(r) => onChange({ ...value, [k]: r })}
          />
        </div>
      ))}
    </div>
  );
}

/** "Retry & backoff" tab: global defaults for all five layers. */
export function RetryPolicyPanel() {
  const [policy, setPolicy] = React.useState<LLMRetryPolicy>(ZERO_POLICY);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const p = await api.llmRetryPolicy();
      setPolicy({ ...ZERO_POLICY, ...p });
    } catch (e) {
      toast.error(`Failed to read retry policy: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function save() {
    if (saving) return;
    setSaving(true);
    try {
      // The backend clamps out-of-range values and returns them; refresh with the returned values so what you see is what is saved.
      const saved = await api.saveLLMRetryPolicy(policy);
      setPolicy({ ...ZERO_POLICY, ...saved });
      toast.success("Saved and effective immediately (the current call retains its existing parameters)");
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  const set = (k: LayerKey) => (r: LLMRetryRule) => setPolicy((p) => ({ ...p, [k]: r }));

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-dashed p-10 text-muted-foreground text-sm">
        <Loader2Icon className="size-4 animate-spin" /> Loading retry policy…
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      <div className="rounded-lg border bg-muted/30 p-3 text-muted-foreground text-xs leading-relaxed">
        Model call failures pass through five retry layers, from inner to outer:
        <span className="text-foreground"> Connection → Empty response → Same-provider safe window → Failover circuit breaker → Intent retry</span>
        . Outer layers apply after inner retries are exhausted, so retry counts
        <span className="text-foreground">multiply</span>
        . Maximizing every layer can consume dozens of requests per transient failure. Blank fields use existing defaults. The first three layers can be overridden per model profile.
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(Object.keys(RETRY_LAYERS) as LayerKey[]).map((k) => (
          <RetryRuleFields key={k} layer={k} idPrefix="gl" value={policy[k]} onChange={set(k)} />
        ))}
      </div>

      <div className="flex gap-2">
        <Button onClick={save} disabled={saving}>
          {saving ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
          Save
        </Button>
        <Button variant="outline" onClick={() => setPolicy(ZERO_POLICY)} disabled={saving}>
          Restore all defaults
        </Button>
      </div>
    </div>
  );
}
