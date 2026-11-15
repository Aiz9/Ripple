import assert from "node:assert/strict";
import test from "node:test";
import { activeMention, mentionKinds, mentionSearch, mentionToken, selectedMentions } from "./chat-mentions.ts";

// Chinese input exercised by the legacy-compatibility tests. Unicode escapes keep the
// source ASCII; each string is identical to the CJK text it stands for.
const ZH_FINDING = "\u6f0f\u6d1e"; // legacy "finding" category alias
const ZH_FINDING_PREFIX = "\u6f0f"; // first character of ZH_FINDING
const ZH_ENDPOINT = "\u63a5\u53e3"; // legacy "endpoint" category alias
const ZH_SELECTED = "\u5df2\u9009"; // "selected"
const ZH_VIEW = "\u67e5\u770b"; // "view"
const ZH_NEXT_LINE = "\u4e0b\u4e00\u884c"; // "next line"

test("mention trigger supports Chinese and cursor placement without hijacking email", () => {
  assert.equal(activeMention("user@example.com", 16), null);
  assert.equal(activeMention(`${ZH_SELECTED} @[${ZH_FINDING}#1 X]`, 12), null);
  // A CJK character directly before "@" still opens a mention (unlike an email local part).
  assert.deepEqual(activeMention(`${ZH_VIEW}@${ZH_FINDING} more text`, 5), { start: 2, end: 5, query: ZH_FINDING });
  assert.equal(activeMention(`@${ZH_FINDING}\n${ZH_NEXT_LINE}`, 8), null);
});

test("categories, Chinese aliases, IP and keyword search", () => {
  assert.equal(mentionSearch("").categories.length, 9);
  assert.equal(mentionSearch(ZH_FINDING_PREFIX).categories[0].kind, "finding");
  assert.equal(mentionSearch(ZH_FINDING).kind, "finding");
  // A CJK alias may be followed directly by the query with no space.
  assert.equal(mentionSearch(`${ZH_FINDING}SQL injection`).query, "SQL injection");
  assert.equal(mentionSearch("ip 192.0.2.1").kind, "ip");
  assert.equal(mentionSearch(`${ZH_ENDPOINT} GET /api`).query, "GET /api");
  assert.equal(mentionSearch("acme.com").kind, "");
});

test("tokens roundtrip labels and removing one reference preserves its neighbors", () => {
  const first = mentionToken({ kind: "finding", id: 12, label: "Title[1]\nDescription" });
  const second = mentionToken({ kind: "ip", id: 13, label: "192.0.2.1" });
  const value = `Analyze ${first} and ${second}`;
  const selected = selectedMentions(value);
  assert.equal(selected.length, 2);
  // Brackets inside a label become parentheses so they cannot terminate the @[...] token.
  assert.equal(selected[0].label, "Finding #12 · Title(1) Description");
  const next = value.slice(0, selected[0].start) + value.slice(selected[0].start + selected[0].token.length);
  assert.equal(selectedMentions(next)[0].token, second);
});

test("all English reference types roundtrip, and saved Chinese references still work", () => {
  for (const item of mentionKinds) {
    assert.equal(mentionSearch(item.label).kind, item.kind);
    assert.equal(mentionSearch(`${item.alias} example`).query, "example");
    const token = mentionToken({ kind: item.kind, id: 12, label: "example" });
    assert.equal(selectedMentions(token)[0].token, token);
    assert.equal(selectedMentions(`@[${item.legacyLabel}#12 example]`).length, 1);
  }
});
