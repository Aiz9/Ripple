// legacyLabel is the Chinese category name used by older saved messages; it is
// still accepted as typed input and parsed in saved references. The values are
// unicode escapes so the source stays ASCII.
export const mentionKinds = [
  { kind: "finding", label: "Finding", alias: "finding", legacyLabel: "\u6f0f\u6d1e" },
  { kind: "asset", label: "Asset", alias: "asset", legacyLabel: "\u8d44\u4ea7" },
  { kind: "company", label: "Company", alias: "company", legacyLabel: "\u4f01\u4e1a" },
  { kind: "endpoint", label: "Endpoint", alias: "api", legacyLabel: "\u63a5\u53e3" },
  { kind: "ip", label: "IP", alias: "ip", legacyLabel: "IP" },
  { kind: "app", label: "Application", alias: "app", legacyLabel: "\u5e94\u7528" },
  { kind: "root_domain", label: "Domain", alias: "domain", legacyLabel: "\u57df\u540d" },
  { kind: "subdomain", label: "Subdomain", alias: "subdomain", legacyLabel: "\u5b50\u57df\u540d" },
  { kind: "service", label: "Service", alias: "service", legacyLabel: "\u670d\u52a1" },
] as const;

export type MentionKind = (typeof mentionKinds)[number]["kind"];
export interface ChatMention {
  kind: MentionKind;
  id: number;
  label: string;
  description: string;
}

export function activeMention(value: string, caret: number) {
  const before = value.slice(0, caret);
  const start = before.lastIndexOf("@");
  if (start < 0 || (start > 0 && /[\w.+/-]/.test(before[start - 1]))) return null;
  const query = before.slice(start + 1);
  if (/[[\]\r\n@]/.test(query) || query.length > 220) return null;
  return { start, end: caret, query };
}

export function mentionSearch(query: string) {
  const text = query.trimStart().toLowerCase();
  for (const item of mentionKinds) {
    for (const alias of [item.label.toLowerCase(), item.alias, item.legacyLabel]) {
      if (text === alias || text.startsWith(`${alias} `) || (/[^a-z]/.test(alias) && text.startsWith(alias))) {
        return { kind: item.kind, query: query.trimStart().slice(alias.length).trim(), categories: [] };
      }
    }
  }
  const categories = mentionKinds.filter(
    (item) => item.label.toLowerCase().startsWith(text) || item.alias.startsWith(text) || item.legacyLabel.startsWith(text),
  );
  return { kind: "" as const, query: query.trim(), categories };
}

export function mentionToken(item: ChatMention) {
  const kind = mentionKinds.find((entry) => entry.kind === item.kind)?.label ?? "Asset";
  const label = item.label
    .replace(/[[\]]/g, (char) => (char === "[" ? "(" : ")"))
    .replace(/\s+/g, " ")
    .slice(0, 100);
  return `@[${kind}#${item.id} ${label}]`;
}

export function selectedMentions(value: string) {
  // Keep saved Chinese references (legacy labels, see mentionKinds) readable while new references use English.
  return [
    ...value.matchAll(
      /@\[(Finding|Asset|Company|Endpoint|IP|Application|Domain|Subdomain|Service|\u6f0f\u6d1e|\u8d44\u4ea7|\u4f01\u4e1a|\u63a5\u53e3|\u5e94\u7528|\u57df\u540d|\u5b50\u57df\u540d|\u670d\u52a1)#([0-9]+)(?: ([^\]\r\n]*))?\]/g,
    ),
  ].map(
    (match) => ({
      token: match[0],
      label: `${match[1]} #${match[2]}${match[3] ? ` · ${match[3]}` : ""}`,
      start: match.index,
    }),
  );
}
