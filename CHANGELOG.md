# Changelog

Notable changes are recorded in this file; the format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). These entries are the release history inherited from upstream ARTEX, on which Ripple is based; environment variables written `ARTEX_*` below are named `ANDROIDLAB_*` in Ripple (for example `ANDROIDLAB_PG_DSN`).

## [Unreleased]

## [0.3.15] - 2026-10-07

### Interception

#### Added

- **New built-in interception rule "delete-style API paths"**: the built-in destructive-HTTP rule used to recognize only the DELETE **method**, yet most applications' delete endpoints can be triggered with GET/POST, so calls like `curl 'http://t/api/user/delete?id=1'` would really delete target data. A `deny` rule now covers `/delete /del /remove /unlink /erase /destroy` (the verb must be followed by a separator, so `/delivery`, `/details` and `/delta` are not blocked by mistake). Existing instances get it on upgrade too; it can be disabled or deleted under "System -> Command interception".
- **Token consumption of model fallback approval can be viewed separately**: approval calls previously had no separate metering, so their cost could only be guessed. They are now metered on their own, and a usage card below the "Model fallback approval" switch under "System -> Command interception" shows cumulative call count, input, output, and cache read/write, plus a mini bar chart of daily consumption over the last 30 days.

### Finding notifications

#### Added

- **Findings can be pushed to IM**: a new "System -> Notifications" page pushes scan findings to six channels: **DingTalk, Feishu, WeCom, generic webhook, Telegram and email**. Any number of instances can be configured per type, each with its own enable switch, rate limit and filter rules.
- **Realtime and digest delivery modes**: realtime sends each finding as soon as it matches; digest merges findings into one message per global period (default 30 minutes), opening with the number of new findings and the severity distribution. For "critical in realtime, everything else in a digest", create two channels configured separately.
- **Filter rules along four dimensions**: minimum severity, restricted task/asset scope, vulnerability-type keyword include and exclude (exclude wins), and whether to receive disposition status changes (off by default). Messages carry a "View details" button whose target comes from the global "link-back URL"; with it empty, no button is added.
- **Delivery history and manual resend**: lists each delivery's status, attempt count, failure reason and channel, filterable by channel and status; failed items can be resent in one click (resending resets the retry count).
- **Masked display of channel credentials**: webhook URLs, signing secrets, bot tokens, SMTP passwords and the like are echoed only as masked values with a trailing hint; sending one back unchanged means "do not modify", and clearing the input deletes the field.

#### Fixed

> This section is the outcome of a security audit after the first version of the feature; every item was reproduced first, then fixed, then covered by a regression test.

- **Fixed masking bypass via "change the target address, keep the credentials" (critical)**: config merging kept the stored value for any key not mentioned, so changing only the address and staying silent about credentials made the server send the real stored credentials to an arbitrary address, completely silently. Now, once the target address changes, every credential field must be stated explicitly -- either a new value, or explicitly left empty meaning it is no longer needed.
- **Fixed zero escaping of untrusted content in markdown-style channels**: finding titles and summaries come from model output and asset URLs from scan results, so a crafted title would render as a clickable external link in DingTalk / WeCom / Feishu, and image syntax would be fetched by the client on render, leaking the reader's IP. Content is now flattened to a single line with markdown metacharacters escaped, and escaping happens at each channel's render output rather than in the shared title function.
- **Fixed the SSRF surface of delivery addresses**: loopback, internal and cloud-metadata addresses were all deliverable, and the first 200 bytes of a failure response went into `last_error` and were echoed by the delivery history, forming a semi-blind read primitive. Protection now happens at **dial time**, covering DNS rebinding and rejecting cross-host redirects; loopback and link-local addresses require explicitly setting `ARTEX_NOTIFY_ALLOW_LOCAL=1`, while RFC1918 private networks remain allowed (self-hosted internal SMTP relays are common).
- **Fixed notification credentials leaking through error messages**: DingTalk's `access_token`, WeCom's `key` and Telegram's bot token all live in the URL, and on delivery failure the full URL flowed into `last_error`, the delivery history, server logs and front-end messages. All of these are now redacted, keeping only `scheme://host` and the underlying reason.
- **Fixed silent loss when a truncated digest marked the whole batch as delivered**: truncated findings were neither in the message nor in the failure list, yet the delivery history showed success. Messages are now packed by **whole entries**, only the entries that fit are marked, and the rest go back to the queue for the next message without consuming retries; the message header also states how many will continue in the next one.
- **Fixed a typo in the minimum-severity threshold silently disabling the filter**: with `min_severity` mistyped as `hgih`, the unknown level's ordinal was 0 and the check degraded to always true, so users who thought they were receiving only high severity got every finding pushed into the group. The value is now validated on the write path, listing the allowed values.
- **Fixed `rate_per_min = 0` (unlimited) being unreachable**: the storage layer silently turned an explicit 0 into the default, so operators who thought they had lifted the limit were still throttled. The default is now filled in at the API layer only when the field is missing.
- **Fixed digest channels completely bypassing the token bucket**: `rate_per_min` had no effect at all in digest mode. The number of items claimed is now bounded by both this round's quota and an in-memory upper limit.
- **Fixed failure handling judging by the batch's maximum attempt count, dragging new deliveries down with old ones**: an old delivery already retried twice would drag brand-new deliveries in the same batch into failed, so new findings were lost permanently without a single retry. The decision is now made per entry.
- **Fixed deliveries with unparseable snapshots in a digest batch being silently marked successful**: such entries were skipped at render time but counted as successful with the batch. They are now explicitly failed with a reason.
- **Fixed per-channel deliveries per round possibly exceeding the lease duration**: in multi-instance deployments, rows whose lease expired were claimed again, sent twice and had their attempt count incremented twice. The per-round limit is now derived from "lease / single timeout", with an assertion pinning down the relationship between these constants.
- **Fixed Telegram truncation possibly cutting HTML entities**: truncation avoided half-tags but not entity fragments like `&amp`, which could make the parser reject the **entire** message. Both are now avoided.
- **Fixed the email channel treating temporary SMTP failures as permanent**: 4xx codes such as greylisting `450` are temporary rejections that should be retried later, but were all treated as fatal, so servers with greylisting made every notification fail after its first attempt. The first digit of the reply code now decides: 4xx is retryable, 5xx is permanent.
- **Fixed submitting nested structures actually writing mask literals to the database**: object fields like `webhook.headers` can only be masked or submitted as a whole; a mask sentinel placed inside the object was stored as a real value, silently breaking authentication. Such submissions are now rejected explicitly.

#### Design notes

- **The finding-writing transaction does a single blind INSERT**: `notification_events` is written in the same transaction as the finding, so commit guarantees both are atomically consistent. This INSERT deliberately does not read the channel table or run user filter rules and is wrapped in a `SAVEPOINT` -- otherwise one misconfigured filter could abort the transaction and keep a critical finding out of the database.
- **Delivery uses lease-based claiming instead of long transactions**: after `FOR UPDATE SKIP LOCKED` claims rows, they are set to `sending` and `next_attempt_at` is pushed into the future as a lease, so no database lock is held during delivery; rows left behind by a crashed process are reclaimed once the lease expires, self-healing without infinite retries.
- **Rate limiting does not consume the retry budget**: this round's quota is computed from the token bucket first, and then exactly that many rows are claimed. The reverse order would charge an attempt to deliveries blocked by rate limiting, and three attempts' worth of budget would be burned by pure waiting before they landed in failed.

### Test infrastructure

#### Fixed

- **Fixed permanent leftover assets caused by the cleanup order in the company ICP ownership test**: `defer d.Close()` ran first when the function returned and `t.Cleanup` ran after it, so every cleanup statement hit an already-closed connection, the errors were discarded, and test assets and companies were left in the database forever -- also making other tests that assert on asset counts fail mysteriously. Closing the connection now also goes through `t.Cleanup`, registered first, and cleanup failures are surfaced.

### Traffic

#### Added

- **Traffic list supports content search, path / status code / length filters and column sorting**: the filter row supports filtering by **response content** (using the full-text index), **path**, **status code** (exact value or buckets like `2xx`) and **response length range**; column headers sort by time, status code and response length, with the sort preference remembered locally. Two new indexes take effect automatically on upgrade; the agent tools' query contract is unchanged.
- **New "Clear all" in the traffic list**: deletes every traffic record in one go (ignoring the current filters), cleans up historical host directories no longer tracked by the index, then runs a full compaction and reports how much space was actually freed. Traffic evidence bound to findings lives in a separate evidence store and is unaffected.

#### Fixed

- **Fixed disk space not being released after deleting traffic**: the index database was created without `auto_vacuum`, so the file never shrank; the full-text index is also `contentless_delete`, where `DELETE` only writes tombstones without reclaiming the original postings -- deleting traffic actually made the index grow (measured: 6MB of captured bodies -> 16MB index, still 16MB after deleting everything). Newly created index databases now enable `auto_vacuum=incremental`, and after each delete a background job merges the full-text index and runs incremental reclamation in chunks, gradually returning space to the system (the same scenario drops back to 104KB); reclamation releases the write lock between chunks and never blocks traffic recording.

> Upgrade note: `auto_vacuum` can only be set when a database is created, so **existing instances' index databases stay in the old mode** and incremental reclamation is a no-op on them (a one-line notice is printed at startup). On such databases tombstone growth stops after the upgrade, and the space already used can be reclaimed once with "Clear all" -- that step converts the database to incremental reclamation, after which routine deletes take effect on their own.

### LLM

#### Fixed

- **Fixed the custom session header not taking effect on "one-off LLM call" paths**: goal decomposition (round 0) and cold-node compaction are one-off calls without a transcript store, so the context had no session id and gateways could not read the header -- on endpoints like opencode zen that reject a missing header with 400, this showed up as "round 0 fails while later planner rounds work fine". These two paths now explicitly attach a session id that is stable per exploration, which also lets their token usage be attributed to the right exploration (previously it was not recorded at all).

### Tools

#### Fixed

- **Fixed output truncation not applying to MCP and custom tools, letting large results flood the context**: MCP tool results were never truncated, and HTTP custom tools received an empty tool context and so always used a hard-coded 6000 characters instead of the session's configured limit. Both paths now go through `actool.Capture`: truncated to the session's `MaxOutputChars` (default 30000), and with `ToolOutputDir` configured the full output spills to disk while the message keeps only the opening fragment and a file pointer.
- **Upgraded norma to v0.4.3**: the harness layer runs `CaptureOnce` uniformly, so no tool (including future ones) can flood the context by missing truncation.

### Deployment

#### Fixed

- **Fixed the activity stream failing to connect behind a reverse proxy**: the SSE address was unconditionally built as `${hostname}:8787`, so in deployments reverse-proxied to 443 the page loaded from `https://domain/` while SSE pointed at port 8787, which was not exposed publicly, and the activity stream kept reconnecting. It now depends on `NODE_ENV`: production defaults to same-origin, and only `next dev` keeps `:8787` to bypass Next.js buffering of SSE; the `NEXT_PUBLIC_SSE_BASE` override remains. The README gained reverse-proxy deployment notes.

### Findings

#### Fixed

- **Fixed the "By asset" view's asset list having no scrollbar when it overflows**: the outer card only had a `max-height` and no definite height, so the scroll viewport's percentage height could not resolve, and with many assets the list either burst out of the card or was cut off without scrolling. The height limit now sits directly on the asset tree's native scroll container and adapts to the window height.

### Database

#### Fixed

- **Capped the connection pool**: `database/sql` does not limit how many connections the application itself opens by default, and creates new ones unconditionally when the pool has none idle, all the way up to PostgreSQL's `max_connections` (default 100) before being refused. It is now capped at 32; excess queries wait for an idle connection, so the same load shows up as slower rather than as errors. If `max_connections` was lowered, lower this too.
- **Improved connection reuse**: `MaxIdleConns` defaults to 2, so with more than 2 concurrent connections each was closed after use and the next request had to redo the TCP and PostgreSQL authentication handshake. The idle limit now equals the total limit, with a 30-minute connection lifetime and 5-minute idle eviction so the pool naturally replaces long-lived bad connections.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.14] - 2026-09-24

### Task list

#### Added

- **New "Findings" column in the task list**: shows counts by severity tier -- critical / high / medium / low -- with non-zero tiers colored by severity, so each task's finding volume and distribution are visible at a glance.

#### Changed

- **Narrower "Description / Goal" columns**: overlong content is truncated and the full text appears on hover, so long text no longer takes over the list's horizontal space.

### Exploration graph and planning situation overview

#### Changed

- **Slimmed the planning situation overview (graph_overview) and capped every list**: recent facts, finished intents, pending intents, cold-area digests and confirmed finding details now show "the latest window + a count fallback", with the rest queryable on demand; this markedly reduces each round's LLM context size and keeps long tasks' context from ballooning (cold areas in linked-task overviews are limited too).

#### Fixed

- **Removed reverse duplicate edges between digests and findings in the exploration graph after cold nodes are folded**.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.13] - 2026-09-19

### Asset interception

#### Added

- **New global asset interception rules (blocklist)**: exact and fuzzy domain / IP / URL rules and CIDR ranges can be entered, with create/read/update/delete and enable/disable; the management page is under "System -> Asset interception". Fuzzy blocking of government (`.gov` / `.gov.cn`) and education (`.edu` / `.edu.cn`) sites is built in by default.
- **Asset interception wired into the execution chain**: before dispatching intents (`add_intent`) and inserting assets (`insert_assets`), agents first run an interception check on the target asset -- blocked intents are not dispatched, blocked assets are not inserted, and the agent is told the asset and the reason.
- **New task-level block / allow (allow-list) rules**: independent of the global rules and effective only for that task, evaluated "block first, then allow" -- a block match forbids testing; with no block match but allow rules configured for the task and none matching, the target is "not allowed to test"; without allow rules the allow-list is off. Rules can be entered when creating a task, and added, edited, deleted, enabled or disabled in the task detail "Overview".
- **Task templates support a preset category and task-level block/allow rules**: a template can save a task category and a set of task-level rules, carried into the new-task form when the template is applied.

### Operation review

#### Fixed

- **Tightened the model judge's output protocol to reduce wrong approvals caused by truncation**: the decision explanation (comment) limit dropped from 500 to 120 characters, with "output only JSON, no preamble or code block" enforced, so a verdict truncated by `MaxTokens` no longer becomes unparseable and gets allowed under the model-failure policy (fail-open).

### Task archiving

#### Fixed

- **Archiving skips symbolic links instead of failing the whole package**: the archive format only supports regular files and directories end to end, and any symlink in the working directory used to fail the entire task archive; the symlink is now skipped and logged while the other files archive normally (links are not followed and never escape the directory tree).

### Accounts and compliance

#### Added

- **New "Terms of use and disclaimer" dialog before login**: login is allowed only after ticking agreement.

### License and dependencies

#### Changed

- **The project adopts the AGPL-3.0 license**, with the README's license and disclaimer sections improved.
- **Upgraded norma to v0.4.1**.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.12] - 2026-09-17

### Exploration broadcast board

#### Added

- **New "Exploration broadcast board" on the task detail page** (#144): presents the task's exploration nodes (start/goal/intent/fact/finding/hint/digest) as a timeline stream, with type filters, keyword search, ascending/descending order, paging and auto-refresh. On "page 1, newest first" it is the live position and refreshes every round; away from it only an unread count accumulates without disturbing your reading, and "N new broadcasts - back to latest" returns in one click. Grouped by day, so even paging through a long task shows which day something happened.
- **Each broadcast row shows the node id** (#145), making it easy to cross-reference the exploration lineage graph and locate a specific node.
- **Expanding a broadcast shows upstream/downstream and anchored assets** (#147): expanding an entry shows the node's upstream (where it came from) and downstream (what it produced) relationships; hovering a related entry pops up that node's card (type/status/source/time/summary/payload excerpt), and the assets anchored by the node are listed too (type label + recognizable text). The related data arrives with the broadcast page, so expanding sends no extra request.
- **Broadcast search supports filtering by node id** (#150): besides "content / source", the search box matches node ids; typing a plain number or the "#41" form shown in the UI locates the node precisely.

### Intent management

#### Added

- **Intent deletion supports "soft delete / hard delete"** (#149): unclaimed, running and paused intents can all be deleted, a reason is required, and the mode is chosen in the confirmation dialog.
  - **Soft delete (default)**: the intent is set to "Deleted" with the reason stored in a separate field, keeping the intent node and all its outputs and lineage.
  - **Hard delete**: physically removes the intent and the descendant nodes "supported only by it" (cascading along output / intent chains to the leaves), leaving no orphaned data; the deleted intent's token metering is archived under its original date; shared nodes (still referenced by other intents), goals and the task root fact are always kept, and the hard-delete dialog shows how many nodes the cascade is expected to affect.

  Both modes tell the planner "this intent was deleted by the user + reason" and replan accordingly.

### Operation review

#### Added

- **Approval records can be filtered by status and decision source** (#139): filter approval records by approval status and decision source to find the target record quickly.

#### Fixed

- **Pending approval requests load independently of history paging** (#133): pending requests are no longer affected by history-list paging and stay fully visible while browsing history.

### Agent

#### Changed

- **The worker role description now uses generic cybersecurity-platform wording** (#138).

#### Fixed

- **Fixed cold-node compaction never triggering**: the per-task planner now has a Compactor attached; cold-node compaction (cold-digest) never ran because it was not wired in, and is now restored.

### Chat

#### Added

- **Chat supports @-mentions of several record types with scroll paging** (#135): several kinds of records can be @-mentioned in chat, and mention candidates load with scroll paging.

#### Fixed

- **Long message bubbles stay inside the conversation panel** (#137): overly long message bubbles no longer overflow the conversation area.
- **Fixed "missing upload file" when uploading before a new conversation is created**: the Composer's file picker now snapshots the `FileList` into an array before clearing the input and calling back; previously a draft first had to create the conversation asynchronously, and by the time it resumed the `FileList` live-bound to the input had been cleared, so the upload lacked the file field and the backend returned 400.

### Traffic

#### Fixed

- **The traffic recording proxy listens only on 127.0.0.1 by default** (#129, #130): avoids exposing an open proxy on other network interfaces in the default configuration.

### Web

#### Fixed

- **Fixed the static-export task list page losing the global header**.
- **Added the missing linked-traffic mock for the demo finding detail page, fixing a blank screen**.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)
- [@dingpotian](https://github.com/dingpotian)

## [0.3.11] - 2026-09-15

### Operation review

#### Added

- **Approval records can locate their source** (#125): clicking an approval record's "Source" jumps back to the tool execution that triggered the approval -- it opens the original full session, auto-pages to the target position, expands the command and result in place and centers and highlights it in the scroll area, keeping surrounding messages readable; automatic correction stops when the user scrolls manually. Across regular conversations, task workers, the planner and main-agent segmented sessions, the exact location comes from the persisted `tool_use_id` and task mapping (with a new scoped call-ID index); missing, duplicate or ambiguous links are reported explicitly instead of jumping to another execution. A clear message is shown when the session was deleted, the task archived or the record is missing.
- **Approval records support paging** (#115).

#### Changed

- **Slimmed the model review input** (#124, #125): the model review (the LLM judge after no rule matched) input is now a versioned JSON of "the current complete tool call + explicitly chosen short background + the local working directory". Background only takes real user messages (the current user message of a chat/task main agent); workers no longer attach the intent summary, and background inherited from a parent agent is cleared; the planner and auto-triggered sessions do not fabricate user messages. The task description, goal, operating constraints, global exploration situation, call history and the worker's full intent are no longer included -- they are still used for agent execution and separate session audits as before, just not for operation review. Every verdict must output JSON `decision`/`comment`, and the explanation must cover "the actual operation, the consequence if it succeeds, and the rule matched"; instructions inside arguments or background cannot change the review policy. The input snapshot actually sent to the model is saved with a fingerprint; old snapshots are kept and labeled with their version, and old inputs are never reconstructed from current data.

#### Fixed

- **Model verdicts wrapped in a code block are no longer silently allowed** (#126): if the model wrapped its verdict JSON in a ``` code block, parsing used to fail and the call was silently allowed through the model-failure policy; the code fence is now stripped before parsing, and only if parsing still fails is the configured failure policy applied.

### Agent

#### Added

- **New experimental noa context compaction** (norma upgraded to v0.4.0): an experimental feature that can be enabled in system settings, off by default. When on, noa (model-driven context compaction) takes over context compaction for the main agent, planner, worker and chat agents, replacing the built-in compaction; compaction source text is archived persistently under `<workDir>/noa/<session ID>/` (not scattered across task directories), one globally unique directory per session ID. If wiring it in fails it falls back to the built-in compaction without interrupting real tasks; the switch is read once per run, so toggling affects only runs started afterwards.

#### Fixed

- **Exploration graph tools refuse instead of crashing on nil without a task context**: calling exploration-graph tools outside a task context returns an explicit error instead of crashing on a nil store dereference.

### MCP

#### Added

- **Support for legacy SSE MCP servers** (#117): compatible with MCP servers that only offer the old SSE transport.

### Traffic

#### Fixed

- **Traffic search matches record hosts port-aware** (#114): `traffic_search` host matching includes the port, so records for the same host on different ports no longer bleed into each other.
- **A failed `traffic_search` description migration no longer interrupts later reporter migrations**: a single failed migration is isolated and does not affect the following ones.

### Web

#### Changed

- **Added dividers between task retest finding options** (#122): retest finding choices are separated for visual clarity.

#### Fixed

- **Fixed the demo task detail page crashing entirely**: in mock mode the task detail "Sessions" tab fetched `GET /api/tasks/<id>/side-questions` (side-question history), but the mock handler had no such route, so the read fallback returned `[]` because "a path ending in s is a collection", leaving `data.items` as `undefined`; iterating it in the side hook's `merge()` threw `TypeError: t is not iterable`. That exception happened inside a `setItems` updater, was deferred by React to the render phase and rethrown out of the caller's `catch`, and the error boundary took over the whole page showing "This page couldn't load". The mock handler now returns an empty side-question history explicitly, and `sideAPI.history` also normalizes the response (any non-array `items` becomes `[]`) as defense in depth.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.10] - 2026-09-13

### Network

#### Added

- **New official DeepSeek source for web search**: reuses the currently active LLM config directly. It differs from the other three sources -- DeepSeek has no directly callable search API; search exists only inside its Anthropic-compatible API (the `web_search_20250305` server tool) and is executed by DeepSeek's servers. So it **supports only the official DeepSeek endpoint + the anthropic protocol** (OpenAI-protocol endpoints reject server tools outright), every search **costs an extra model call**, requests **do not go through the search egress proxy** and **are not recorded in traffic**, and results contain **only titles and links** (no snippets; use WebFetch to fetch the body when needed). The settings page explains these limits but **does not block** on them; users confirm compatibility themselves and can run a real check with the "Test search" button.

### Agent

#### Added

- **Workers can look back across works**: new `search_all_worker_traces` (searches the execution of every work in this task by keyword for matching steps, without knowing the intent_id first) and `get_worker_trace` (once a work is chosen, lists its step stream, searches it in place by keyword and fetches full content by step_id), so observations other works saw but never wrote into facts can be reused and duplicate work avoided.
- **`node_detail` made available to workers**: together with the look-back tools above, once a worker has an intent_id / node id it can query that node's full details directly.
- **Planning rounds triggered by `add_hint` are announced explicitly**: previously a new hint was only folded into the situation overview for the planner to discover itself; now each `add_hint` records a trigger for the planner -- "a human added N strategic hints: ..." (a batch counts as one, not one per hint) -- so the planner is told explicitly "this round was triggered by new hints" and sees the hint content directly.

#### Changed

- **The global situation prompt now uses a "loosening" tone**: it encourages divergent exploration and prompt reporting of cross-intent leads instead of converging too early.
- **Slimmed the worker boundary wording**: an initial block does not mean the direction is exhausted; focus on "exhausting the bypass techniques within this intent before concluding".
- `insert_assets` drops the per-asset `related` argument: its only effect was deciding whether to add the asset to this task's scope, and the value was never stored (it was voided when the same asset was registered again, and the UI never showed which assets were judged unrelated), so it only made the model perform a judgment that could not be kept.
- **Test scope (`task_scope`) is no longer affected by the asset-coverage switch**: automatic scope entry from `insert_assets` (`source='auto'`) runs whether coverage is on or off, and `add_task_scope` is always available to the planner / in-task main agent / goal decomposition agent. Scope is the task's authorization boundary and the filter basis for asset queries; the coverage switch only decides whether to use it as the denominator for a metric, not whether the scope itself accumulates. Previously turning coverage off disabled both the `auto` and `agent` write paths, leaving `task_scope` with only rows added manually in the UI. `list_untested_assets` is still hidden when coverage is off (it is purely a coverage view).

#### Fixed

- **Fixed assets bleeding between tasks** (#59): `list_assets` used to hard-code the task id as 0 and query the whole shared asset store, and the model had no way to write a scope filter, so it took other tasks' assets (especially IPs) as this task's targets and steered testing off course. It now returns only assets within the test scope (`task_scope`) of **this task and directly linked tasks**, matched by **ownership** rather than literal value: a root domain in scope makes all subdomains/services/endpoints under it queryable, and a network range makes the hosts and services inside it queryable; fetching an out-of-scope asset by id is refused too. Non-task contexts (Auto/pentest) have no scope to rely on and still fall back to the whole store. This also fixes the ownership blind spot where hosts reached directly by IP (such as `http://1.2.3.4/api`) could not be matched by a network-range scope. The UI's "Test assets" view (filtered by task producer) is unaffected.
- **Fixed the worker cross-work look-back tools being unbound by mistake**: after `search_all_worker_traces` / `get_worker_trace` (and `node_detail`) were added to the worker's default tool set, an old migration that "narrowed the worker tool surface" unbound them again at startup, so workers never actually got these tools. They have been removed from that unbind list, and databases that already ran the old migration get them rebound to the worker once.
- **Fixed occasional storage failures of `/btw` side questions**: NUL (`\u0000`) escapes, which JSONB does not support, are stripped before side_question checkpoints are stored, avoiding errors when content contains that character.

### Triggers

#### Fixed

- **Merged trigger sessions de-duplicate task description/goal per task**: when several tasks merge into one trigger, the same task's description/goal is no longer repeated in the message, so long goals do not pile up and blow up the context.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.9] - 2026-09-11

### Agent

#### Added

- The in-task main agent supports **multiple sessions**: create, switch and reset context independently; every session is interactive.
- Persistent `/btw` **side questions**: ask follow-ups without interrupting the main line; Q&A is stored and survives restarts.
- `spawn_task` gains `source_task_ids`, so a new task can **inherit read-only** the source tasks' assets and findings.

#### Changed

- Turned off workers' cross-engagement memory and narrowed their default tool surface: reading context and cross-work review are planning responsibilities; workers only execute and write back a single intent.
- Slimmed the default worker prompt; `get_worker_output` drops the `terminated` and `worker_name` fields; slimmed the `insert_assets` / `list_assets` descriptions.

#### Fixed

- Fixed works stopping early on **idle turns**: the model sometimes spends a whole turn only thinking, producing neither text nor tool calls; the harness sees a natural end (`end_turn` with no `tool_use`) and closes with `completed` + an empty summary -- an unfinished intent is cut off halfway, showing up as "the task ended normally but with no text summary". None of the five LLM retry layers can reach it: it is not an error; same-provider safe-window retry starts from a "stream failure", the circuit breaker counts `err == nil` as success, and intent rerun only reacts to `model_error`; the SDK's empty-response retry cannot reach it either, because that layer judges emptiness by whether any event was yielded, and thinking deltas are events. The work's Stop hook now recognizes such a turn and injects a continuation instruction so the model carries on with the next step using the thinking it already produced -- deliberately not "resend as-is", because these idle turns are usually caused by the prompt and context shape, a stable behavior rather than random flakiness, and resending would only make the model think it through again.
- The count reuses the **empty-response retry count** under "Retry & backoff" on the LLM page (both answer "the model finished without producing substantive content", just with different criteria and remedies), default 2; `-1` turns it off and restores the old "idle turn ends the run" behavior. It is a **total** limit per intent, not a consecutive count: the harness itself already limits consecutive idle turns to a single push, and the quota refreshes only when a real tool turn happens, so this number guards against loops like "tool -> idle -> push -> tool -> idle" exhausting the intent's budget. When it fires the log records `[work <worker>] idle turn (reasoning only, no text/tools); injecting continuation (n/N)`. Design notes are in upstream ARTEX's LLM retry design document, section 1.1.
- Fixed the `/btw` context budget and input layout for long conversations; side request IDs are generated with a fallback in insecure contexts (non-HTTPS access).

### Traffic

#### Added

- Findings can **link multiple pieces of traffic evidence**, reorderable, annotatable and distinguished by role (request/response/supporting).
- The reporter agent **automatically links** relevant traffic evidence before writing the report.
- New agent **traffic binding switch**, plus complete evidence hand-off between agents.

### Tasks

#### Added

- **Session-level finding retests**: retests run in a separate agent session, and the list and detail pages show their run status.

### Interception

#### Added

- Approval records gain **details and execution audit**: view the tool request context, the model/rule initial decision, execution output and the argument fingerprint.

### Assets

#### Added

- Task test assets support **DSL search**.

### LLM

#### Fixed

- Fixed connection tests not sending the custom session header, which made opencode zen return 400.

### Network

#### Added

- HTTP-transport MCP servers can **skip TLS certificate verification**, making it easy to connect services with self-signed certificates.

### UI

#### Added

- The session list is grouped by agent, with expand/collapse and independent pinning; conversations can be filtered by agent.
- The attack lineage graph renders compaction (digest) nodes and collapses their members.

#### Fixed

- Fixed a blank screen caused by unsynchronized login credentials.
- Interception messages now say explicitly "platform control", so they are not mistaken for defenses on the target side.

### Deployment and updates

#### Added

- **One-click update from the UI**: the system settings page gains a "Version & updates" card, and the top bar lights up a hint when a new version exists. The flow is download the release package -> verify `SHA256SUMS` -> smoke test -> stage -> exit and let the supervising script relaunch to complete the swap, with the page refreshing automatically.
- New supervising start scripts `start.sh` / `start.bat` as the official entry point (included in release packages and the Docker image; `install.sh` is unchanged): they decide from the exit code whether to relaunch and forward SIGTERM to artex. The verification and swap logic lives in Go, keeping the scripts simple.
- Automatic failure fallback: if verification or the smoke test fails, the update is discarded and the current version keeps running; if the new version fails to start 3 times in a row it rolls back to the previous version. The settings page also offers manual rollback (note that the database schema is not rolled back).
- Updates accept only GitHub domains over enforced HTTPS, and the release source is not configurable; one-click update is disabled for development builds. GitHub query results are cached for 30 minutes so the top-bar hint does not exhaust the API quota.

#### Known limitations

- Under Docker only the program is swapped, not the image: the toolchain is not upgraded with it, and recreating the container reverts to the image's bundled version; use `docker compose pull artex` when needed.
- `skills/` in the release package is not synced, so built-in skills added in a new version do not take effect automatically.
- Updating means restarting, which interrupts running tasks.

### Dependencies

#### Changed

- Upgraded norma to v0.3.7.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.8] - 2026-09-09

### LLM

#### Added

- New "Retry & backoff" tab on the LLM page: the **count** and **interval** of all five retry layers are configurable. A failed model call passes from the inside out through connect retries (SDK: connection reset / timeout / 429 / 5xx before the stream starts), empty-response retries (SDK: finished normally without any content; openai format only), same-provider safe-window retries (replay after a dropped stream before any output reached the caller), the rotation circuit breaker (cool down and skip after consecutive failures reach a threshold) and intent rerun (the whole intent reruns after a worker ends with model_error); an outer layer is used only when the inner one is exhausted. Each layer has two knobs with uniform semantics: empty = the original default count and exponential backoff; a count uses that count; an interval replaces exponential backoff with a fixed interval; -1 = turn that retry layer off. The first three layers follow the endpoint and can be overridden field by field in each model config (pinning only the interval still inherits the global count); the circuit breaker and intent rerun are process-level and have a single global setting. Changes apply hot after saving, with no restart. Leaving everything empty keeps the current behavior, and old databases are byte-for-byte unchanged after upgrading (new columns default to 0, and a missing settings key means all defaults). Connection tests deliberately do not use these parameters -- they have a hard 30s timeout, and stacking the user's retries on top would only make a working endpoint time out. Design notes are in upstream ARTEX's LLM retry design document.
- Each LLM config supports a custom **session header** (`session_header_key`): when non-empty, every LLM request carries that HTTP header with the current run's session id (`conv-<id>` for chat conversations, `exp<x>-worker-i<intent>` for workers, etc.), for gateways that do prompt caching / sticky routing by session-id header. The session id is read from the request context and injected without changing norma, so even a shared provider sends different header values per session. Old databases get a migration, and the front-end LLM config dialog gains an input.

#### Fixed

- Fixed saving an LLM config failing with `23502` when the session header field was empty: the column is `NOT NULL DEFAULT ''`, and wrapping it in `NULLIF($n,'')` wrote an unfilled header as NULL and violated the not-null constraint; it is now passed through with empty-string semantics.

### Agent

#### Added

- Wall-clock timeouts now **wrap up in place**: relying on norma v0.3.6, when `MaxDuration` is reached the running tool is interrupted and the run continues on a live ctx for the wrap-up turns (writing back what was identified + a summary, ending in timeout), instead of relying on the worker/planner's own `maxDur+90s` external hard ctx that killed stuck runs as `aborted_tools`. Chat uses the same harness and gets the same behavior automatically; mainagent has no `MaxDuration` and is unaffected.
- Stall safety net: when the planner wakes on a heartbeat / no-change wake-up and the whole graph has no open or running intent, its opening message becomes a stall alert stating clearly that no worker is running and no direction is queued, and this round must produce one or more distinct new intents (zero intents is not allowed).

#### Changed

- Restructured the worker prompt: the intent / start instruction / raw JSON of anchored assets moved into the system prompt, rebuilt every round and never compacted away, so a resumed run does not depend on the transcript's first message surviving; the start user message is slimmed to just the global situation overview (degradable, tolerating staleness). The cost is per-intent data in the system prompt and losing cross-intent cache reuse -- a deliberate trade-off for "never lose the intent".
- Slimmed the default planner / worker text and fixed several real-world issues: the planner distinguishes `recent_done` by state (for blocked/exhausted, check the trace before deciding, neither treating it as a dead end nor blindly rerunning), negative conclusions are now "observation / doubtful, not final" with evidence checked before accepting them, an unmet goal with no open/running intent must produce intents (a hard floor), and depth takes priority over coverage; worker negative conclusions only record "observation + tentative reading" with the verdict left to the planner, and cross-intent leads go into the fact's summary for the planner instead of being chased by the worker. Reseeding appends the new default as a new version and switches to it, keeping user customizations / old versions in history for rollback.
- Narrowed the work agent's default tool set and asset write-back prompt: workers only execute and write back a single intent, while reading context / cross-work review are planning responsibilities, so `list_facts` / `node_detail` / `list_companies` and cross-work search (`search_all_worker_traces` / `list_worker_traces` / `get_worker_trace`) were removed from their defaults, keeping only `list_findings` (check for duplicates before reporting) + `add_finding` / `record_fact` + `insert_assets` / `list_assets`; the prompt drops stale field descriptions conflicting with the `insert_assets` schema (`type=tech`/`on_url`/`props`). Old databases get a one-time migration removing those bindings; planner/main bindings of the same names are untouched.

### Exploration graph

#### Added

- **Cold-node compaction of the exploration graph (cold-digest)**: old, long-inactive intents / facts are folded into digest nodes shown in `graph_overview`, while the original nodes are kept forever and can be fully restored by id (lossless storage, only presentation is compressed, folding is reversible). Hot/cold is decided by reverse reachability, where any live branch makes it hot, with R=6 rounds of debounce and grouping by connected components; background compaction (minor folds uncovered cold blocks, major re-compresses from source to merge fragments) has activity re-checks and cooldown mutual exclusion, never runs on the hot path and never overwrites revived nodes. The overview provides `cold_digests` and an asset-indexed `cold_index`, with `expand_digest` / `expand_index` doing restoration. Overviews of linked / inherited tasks reuse their own folded views, and `expand_digest` supports read-only cross-task restoration. `expand_digest` / `expand_index` are given to the planner and main agent only, not to workers. All with old-database migrations.
- `graph_overview` outputs the full `finding_list`: findings are a task's most valuable product and a single task usually has few of them, so the overview now carries all of them (unlike facts, which get only a recent window); the planner/worker sees every confirmed finding each round without calling `list_findings`. Each entry is trimmed to `{id, summary, evidence?, from_intent?, assets?}`, with affected assets given as readable content (url / domain / ip:port) instead of bare ids.

#### Changed

- `graph_overview` no longer lists `hosts`: the coverage block drops the host list (in wide-scope tasks every round carried up to 500 host strings, of limited value for planning decisions), keeping only `host_count`; specific hosts are queried with `list_assets` on demand. A new top-level `done_intents_total` (total finished intents) sits beside `recent_done_intents`, which is truncated to at most 15, so the planner knows whether truncation happened when de-duplicating.

### Tools

#### Changed

- `add_company_scope` is bound to the planner instead of workers by default: defining a company's asset scope is the job of planning / main control / Auto, while workers only execute exploration. New databases seed the default binding to mainagent/planner/auto; old databases get a one-time migration.
- The planner is bound to `list_assets` by default: it now has both `list_assets` (DSL search over the whole store) and `list_untested_assets` (untested in scope); old databases are backfilled once without overriding user unbindings.

### Tasks

#### Added

- New "Running workers" column in the task list: counts the task's intent nodes with `state='running'`, using exactly the same definition as "Running workers" in the task detail overview, and shows 0 when none are running.

### Network

#### Added

- New **global egress proxy** setting: all target traffic can leave through one global proxy (http/https/socks5, with `user:pass` support). With traffic capture on it is the upstream of the MITM recording proxy (traffic is recorded and then sent through the proxy, with both the intercept and pass-through paths using the upstream so the source IP never leaks); with capture off it is injected directly into the agent's bash environment and WebFetch (`proxyEnv` gains `ALL_PROXY` for socks5). The setting lives in the settings KV table (no migration needed), and the front-end system settings page gains a "Global proxy" card, independent of the web search proxy and the LLM proxy.

### UI

#### Fixed

- Corrected the meaning of intent status labels: `exhausted` "exhausted" -> "budget exhausted" (it actually means the run was cut off by the turn/time budget with partial results written back, not that the direction was fully explored), `blocked` "intercepted" -> "execution error" (it actually means model/API/network failure retries were exhausted and the intent was essentially never explored, not a target/WAF block), and added the previously missing `stopped` "stopped" (a work stopped manually by the user).

### Dependencies

#### Changed

- Upgraded norma to v0.3.4: MCP tool output gains truncation and spilling to disk (see `651b961`); the later v0.3.6 supports in-place wall-clock wrap-up.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.7] - 2026-08-31

### LLM

#### Added

- Model configs gain an "Output limit" with a choice of request field name: the limit caps how many tokens a single reply may generate and is sent with every request; 0 (default) = the field is not sent and the server default applies. It is distinct from the "context window" -- that is the model's total capacity, used locally only to compute the compaction threshold, and never appears in requests. The field-name switch only matters for the `openai` (Chat Completions) format: empty (default) sends `max_tokens`, which most compatible gateways accept; official OpenAI reasoning models (o-series / GPT-5) conversely accept only `max_completion_tokens` and reject `max_tokens` with `unsupported_parameter`, so such endpoints need the new field selected manually. The other two formats each have a fixed field name (Anthropic uses `max_tokens`, the Responses API `max_output_tokens`), so the switch is greyed out for non-openai formats and cleared on save. This also connects a path that was never wired up: the planner / worker / chat / main agent / goal decomposition never set an output limit at all -- openai-style requests sent none and Anthropic fell back to the SDK's 8192 -- so adding the setting without wiring it would have had no effect. The value is now resolved from the config every round, like "streaming output", so it takes effect on the next round after a failover. Old databases behave exactly as before after upgrading (the new columns default to 0 and an empty field name).
- Clicking "Test" in the backend now logs every HTTP attempt's status code and the gateway's raw response body to the server log (the body trimmed to 4K), making it easy to diagnose 401s, quota messages, empty frames, returned HTML pages and the like, instead of only seeing the UI's collapsed ok / err. This log does not depend on the "LLM recording" switch.

#### Changed

- A task's LLM config chain can now be changed in any state, no longer restricted to "running / paused / config chain exhausted": after a task ends (done / failed / timeout), main-agent conversations still use this chain, and when a model in it failed it could neither be changed nor could interaction continue. Both terminal-state checks in the backend HTTP and DB transaction were removed, and the front-end dialog allows editing and saving for terminal tasks too. Saving a terminal task no longer reopens quota-blocked intents (those intents would move to open with no worker to run them, and no longer qualify for "rerun intent"); to continue, use rerun intent / add goal, which bring the task back to running.

### Agent

#### Changed

- "Send a message to a running worker to adjust its direction" now reuses the existing pause / resume + transcript resume mechanism, behaving the same as main-agent conversations: previously it used a home-grown intervention persistence protocol that involved the scheduling barrier, the recovery flow and more than ten activity query filters. Now the message is injected through the next round's input, and the intent runs directly in a dedicated goroutine, not limited by the 3-slot worker pool, so it runs as soon as the message is sent; the front end keeps the message box and restores the "Continue directly" button, with sending carried over SSE. No DB schema change. Trade-off: messages live only in memory with no crash recovery, and sending a message may briefly put the task one worker over its concurrency (a rare scenario, acceptable).

### Tasks

#### Fixed

- Fixed out-of-memory (OOM) crashes when archiving large tasks: archiving now streams the snapshot instead of reading the whole task into memory at once; it also closes three recovery gaps on the cold-archive path -- traffic on modern installs lives only in SQLite, and a crash between the PostgreSQL commit and the SQLite commit used to leave an archived task's traffic stuck in hot storage with no way to recover it. A staging journal is now written whether or not historical directories exist, and a missing `journal.json` is treated as discardable.
- Fixed the system becoming sluggish with many tasks: loading conversations and loading the UI had noticeable delays. Queries for the task list, task context and exploration records were optimized together, and the front-end dashboard, chat page and task detail page now make fewer duplicate requests.

### Assets

#### Changed

- Removed the "at most 256 rules" limit on company asset scope: companies whose scope is entered IP by IP or domain by domain easily hit that limit, and hitting it meant splitting them into several companies, while the scope itself is not slower just because it has more entries. The limit was removed in the backend, front end and demo mock; a single rule is still limited to 1024 characters, and the 2 MiB request-body limit stays as a backstop (roughly forty to fifty thousand rules).

### Skills

#### Fixed

- Fixed uploading a skill archive failing with "upload failed: zip: unsupported compression": the Go standard library only ships Store / Deflate decompressors, so bzip2 and Zstandard archives written by compression tools at non-default levels could never be unpacked. Those two decompressors are now added (pure Go, no new external dependency); methods that really cannot be unpacked, such as Deflate64 / LZMA / XZ / PPMd, as well as encrypted archives, are now reported with a clear message before decompressing, naming exactly which file uses which compression method and how to repackage it, instead of throwing the low-level error at the user.
- Fixed in-skill file name validation rejecting non-ASCII (e.g. Chinese) file names: path validation used to be an ASCII allow-list `[A-Za-z0-9-_./]`, so a single Chinese-named file in an archive failed the whole upload with "archive contains an invalid path". It is now a Unicode deny-list: file names in any language and spaces are allowed, while control characters, invalid UTF-8, zero-width and bidirectional control characters (RLO file-name spoofing), `\ % # ? * : " < > |`, and `..` / absolute paths / empty path segments are still rejected, so directory-traversal protection is unchanged. Skill names were relaxed the same way -- ASCII is still limited to lowercase letters, digits and hyphens (the agentskills.io spec), non-ASCII letters such as Chinese can be used directly in skill names, but spaces, dots and path separators are not accepted.
- Fixed Chinese archives made by Windows compression tools unpacking with garbled file names or being rejected outright: such zips do not set the UTF-8 flag and write file names in GBK, so names are now decoded with a GBK fallback before path validation. Quoted frontmatter such as a quoted non-ASCII `name:` value also yields the skill name correctly now.

### UI

#### Added

- New "All findings" flat view on the findings page, now the default, switched with the original "Group by task" view through header tabs: the grouped view needs each task expanded to see its vulnerabilities, a detour when you just want to scan a list across tasks. The flat view is one big cross-task table (10/20/50/100 per page) behaving exactly like the grouped view -- select to export, expand inline to see evidence and the detailed report, rename/reclassify/re-rate inline, change disposition status, deepen, delete. Both views share the stat cards and filter bar, switching keeps the filters, and the current view and filters are remembered locally; polling hits only the current view, and inline changes update both caches so switching never shows stale data.
- New "By asset" view on the findings page: an asset tree on the left (company -> root domain / IP -> subdomain -> service -> endpoint; the company level appears only when an asset really has an owner) and, on the right, the findings under the selected node's whole subtree, sharing the same table and filters as the other two views. The tree includes only assets with findings, filling in the ancestor chain as needed (a finding attached only to the deepest endpoint still builds the levels above), and node counts are subtree aggregates de-duplicated by finding; findings whose asset was deleted or that never had one go into an "Unassigned" bucket. Unlike the other two views the asset view does not poll -- it queries only on entering the view, changing filters, adding/editing/deleting findings on the page, or clicking the tree's refresh button, since the left tree is a navigation structure that need not be recomputed every 5 seconds. Each tree level shows only its increment over the level above (subdomains without the root-domain suffix, services as `https :443`, endpoints as just the path), with the full value in tooltips and breadcrumbs; when there are too many nodes, whole endpoint/service levels are dropped with a notice while counts still roll up.

#### Fixed

- Fixed the session transcript being squeezed and cut off in mobile session details: on narrow screens the session list collapses, giving the width to the transcript itself.

### Dependencies

#### Changed

- Upgraded norma v0.3.2 -> v0.3.3: new `Config.MaxTokensField` lets the OpenAI Chat Completions output limit be sent as `max_completion_tokens` instead (the only key reasoning models accept). The two keys are mutually exclusive and only one is sent; the default is still `max_tokens`.
- Upgraded `golang.org/x/mod` v0.37.0 -> v0.40.0, fixing two dependency security alerts.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)
- [@begininvoke](https://github.com/begininvoke)

## [0.3.6] - 2026-08-27

### LLM

#### Fixed

- Fixed the "non-streaming" switch reverting to "streaming" after saving and reopening (#69): the config list API's DTO omitted the `streaming` field, so the response never returned it, and the front end fell back to the default streaming whenever it read `undefined`; the actual write and DB storage were fine, it just could not be read back. The DTO now includes the field again (without `omitempty`, since `false` must appear in the response too).
- Connection tests now verify the model actually replies, and test with the config's real send/receive mode (#65): previously only HTTP success was checked, so a request that went through but got zero reply from the model (thinking burned the budget / the body was swallowed by a safety policy / a compatibility layer dropped `content`) still reported "connection succeeded", inconsistent with the "no reply" behavior in conversations; and tests always used streaming, so non-streaming configs were actually testing a different channel. An empty reply now fails outright, a success shows the model's reply in the message, and the current streaming switch is included in the test, so "test passed" matches "conversations work".

### Agent

#### Changed

- `list_facts` now uses paging + keyword filtering, so many facts no longer blow up the context in a single call (#74): by default it returns the latest 20, supports `limit` (max 100) / a `before` cursor / a `q` summary keyword, and returns `{facts, total, has_more, next_before}`; overly long summaries are truncated by length (the full text is still available through `node_detail`). The worker / planner prompts were updated to the paging semantics. Old databases get a one-time migration refreshing the new parameter schema in the tool catalog table (`SeedTool` only inserts the first time, otherwise the tool management page would show "no parameters").

### Tools

#### Added

- New tool call statistics on the "Tool executions" page (#72): the toolbar's "Stats" button opens a dialog showing each tool's call count, share and failure count (sorted by count, descending); it uses the list's task / keyword filters, counts the whole result set rather than the current page, and is fetched only when the dialog opens.

### Dependencies

#### Changed

- Upgraded norma v0.3.1 -> v0.3.2: fixes reasoning/refusal being silently dropped from OpenAI-style responses (Responses adds `reasoning_text`), de-duplicates the three reasoning field names, adds bounded retries for empty responses (zero content blocks), and fixes gateway 400s caused by compaction boundaries splitting tool pairs (also repairing existing orphans already baked into transcripts).

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.5] - 2026-08-25

### LLM

#### Added

- Each LLM config can switch between streaming and non-streaming (default streaming): on uses streaming SSE; off uses true non-streaming (`stream:false`, the complete JSON returned at once), which works around some gateways' poor SSE implementations (empty frames, dropped thinking fields), at the cost of losing live progress and live token counts while running. worker / planner / mainagent / chat / goals all read the value from the currently active config dynamically; the three provider wrapper layers `llmpool` / `llmrec` / task runtime all support non-streaming; `llm_profiles` gains a `streaming` column with an `ALTER` for old databases (default `true`, transparent for old configs).
- Support for OpenAI Responses API format LLM configs: each config gains a third format `openai-responses` (calling `POST /v1/responses`), alongside Chat Completions / Anthropic; `BaseURL` is normalized and the default model is `gpt-5`; the `format` constraint of `llm_profiles` adds `openai-responses` with an idempotent migration for old databases; the front-end format dropdown gains "OpenAI (Responses API)". Dependency upgraded to norma v0.3.1 (including a `reasoning_content` pass-back fix).
- Recording the raw HTTP of LLM requests/responses: the real wire body is captured at the HTTP transport layer, keeping the tool schemas, `tool_use` blocks and raw SSE frames that the normalized view cannot show; every attempt of norma's internal retries is kept; `llm_records` gains `raw_request` / `raw_response` columns with an `ALTER` for old databases; the recording page's detail panel gains a "Raw" view toggle and request/response copy buttons (with an `execCommand` fallback for insecure contexts).

### Conversations

#### Changed

- Multi-select in the conversation list is now a "Select multiple" mode toggle: the list no longer shows a checkbox on every row by default (cleaner), and the header becomes "N total + Select multiple"; clicking it enters selection mode (checkboxes, select all, bulk delete), "Done" exits and clears the selection, and a fully successful bulk delete exits automatically (with failures it stays in selection mode for a retry); single rename / pin / delete still go through each row's ... menu.

### UI

#### Changed

- Improved task management, conversation actions and traffic viewing (#57): the task list's column sort preference is remembered, inline rename is triggered directly by an icon (no longer through a menu), and drawer (sheet) interactions and traffic-viewing details were refined.

#### Fixed

- Worker asset labels show only domains and IPs, and empty labels are handled correctly.

### Agent

#### Added

- "Quantified acceptance check" when the planner judges goals: when a goal has quantifiable acceptance criteria (asset test coverage reaching X%, capturing N flags, obtaining some permission), the planner must check the measured values in `graph_overview` (`coverage.pct`, finding counts, etc.) before `prove_goal`; if they fall short, `prove_goal` is forbidden and intents are dispatched to close the gap instead, never marking met early on the grounds that "the main part is done / it is mostly achieved". This fixes a goal requiring 100% coverage being judged complete at a measured 40%.

#### Changed

- Rewrote the basis for "zero intents this round" in the planner prompt: the old text called zero intents "the most common and most important principle", which made the planner give up too early while goals were unmet and untested surface remained in scope. Zero intents should now be produced only in two specific cases: (1) every direction considered is already covered by open/running/recent_done intents; (2) the next step depends on output from a currently running work that has not appeared yet (wait for it to finish and plan on the next wake-up after the graph updates). A reverse constraint was added too: when there truly is an uncovered new direction that does not depend on running work, or the goal is unmet and untested surface remains, do not stop because "zero intents is common".
- Strengthened the "evidence threshold for negative conclusions" in the worker prompt: for negative conclusions such as "not injectable / port closed / no login entry" that might make the planner abandon a whole direction, the reasonable techniques within the intent (different encodings/parameters/paths/methods) must be exhausted before concluding; when techniques were not exhausted or the evidence is weak, mark it `confidence=inferred`, so a hasty `observed` negative does not seal off a whole route (wrong negatives early in a task especially steer the direction off course and rarely self-correct).
- The planner / worker default prompt changes above are appended as new versions and made current through one-time migrations (`reseedPlannerPrompt` / `reseedWorkerPrompt`, each guarded by a settings flag); old versions are kept in the version history, and users who customized their prompts can restore them from the version records.

### Operations

#### Added

- New `reset-password.sh` to reset the administrator password (the username is always `ARTEX`): supports local / docker deployments, with connection settings given explicitly or read automatically from `--dsn`/`$ARTEX_PG_DSN`/`config.json`; it generates a bcrypt hash compatible with the backend login inside the database with `pgcrypto` and writes it back to `settings.auth.password_hash`, with no service restart needed after the reset. The password is passed through an environment variable, never in the process argv, and escaped against injection.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

## [0.3.4] - 2026-08-24

### UI

#### Added

- After selecting several tasks in the task list, their category can be changed in bulk, with "Uncategorized" available as a target to remove tasks from their current category; the whole batch is written in one transaction, so failures can only be tasks deleted after being selected.

#### Changed

- "Task category" in the new-task form changed from a dropdown to a searchable input: typing filters existing categories, pressing Enter on a name that does not exist (or clicking "Create" in the dropdown) creates and selects it immediately, and the selection shows as a removable tag; still limited to a single category.

### Conversations

#### Fixed

- Fixed sending a message being blocked by "LLM not configured, cannot chat" when the conversation had an LLM config selected but there was no global active config. The pre-send check looked only at the global active config while actual execution prefers the conversation's selected config -- two inconsistent resolution paths; they now share the same logic (conversation/agent binding first, global as fallback).
- The "cannot chat" message is now specific to the state: with no config at all it says "add a config", with configs but none active it says "activate one or choose one for this conversation", instead of always saying "not configured", which makes the cause easier to find.

### Agent

#### Added

- For tasks whose goals are all achieved, intents dispatched by the main agent through `add_intent` can be claimed and executed directly by workers and stop when finished: the planner no longer runs in that state (a task with no open goals does not enter planning), so it cannot re-judge the goals as met and cancel the intent just dispatched; once the frontier drains the task returns to completed. Before dispatching, the main agent asks the user, based on the intent's content, whether to register it as a formal goal; if registered, the task resumes normal autonomous planning.

#### Changed

- `get_worker_trace` / `get_task_worker_trace` no longer error when `step_ids` exceeds the per-call limit (5); they return the full content of the first 5 steps and report through `returned_step_ids` / `omitted_step_ids` / `notice` which were returned and which were not, with a hint that "no further fetching is needed if this is enough". Duplicate and invalid ids are de-duplicated and removed before counting.

#### Fixed

- The task list is now sorted by task id descending (newest first), replacing the old sort by creation time. Several tasks created at the same moment had identical timestamps and an unstable order, which -- combined with 10-second polling and random map iteration -- made them swap places in the list frequently.

### Assets

#### Fixed

- Fixed company ownership recalculation being broken by a single dirty row: when `assets.ip` held a hostname (written by an agent or the asset API), `a.ip::inet` raised `22P02`, so adding/editing company asset scope and deleting companies all failed and rolled back. The safe conversion `try_inet()` is used instead, skipping invalid values rather than aborting the whole statement.
- Unparseable `ip` values are no longer skipped silently: after saving company scope, the UI states clearly how many assets have an `ip` that is not a valid IP (with their ids and values), warning that these assets will not be attributed by IP/CIDR rules; the same information is also written to the server log, covering paths with no front-end response (deleting companies, scopesentry sync, agent writes).
- IP/CIDR matching for task test scope also switched to `try_inet()`, replacing a regex guard that only checked the character set (hostnames made entirely of hex letters, such as `abc.def`, still slipped through and triggered the same error).

#### Changed

- The `ip` field of `ip`, `service` and `endpoint` assets no longer accepts hostnames: `insert_assets` and the asset API return per-item errors with an `index` and the fix directly (use `type=subdomain` with `domain`, or resolve the A/AAAA record first), so the agent can correct and reinsert on its own. Other assets in the same batch are unaffected and stored as usual.

### Contributors

- [@neouks](https://github.com/neouks)

## [0.3.3] - 2026-08-23

### Worker

#### Added

- Running workers can be paused, resumed and cancelled individually; pausing keeps the intent, facts and findings, while cancelling transactionally cleans up the current intent and its direct outputs after execution exits.
- Added the `paused` intent state, an execution fence and named termination reasons, preventing late blackboard writes after a pause, cancel or task deletion.
- Added an optional task concurrency limit; creating, resuming, deepening findings and queue backfill all go through one persisted FIFO admission path.

#### Changed

- The default wall-clock duration of a single worker run changed from 600 to 1200 seconds; a timed-out task that is revived restarts its clock on the next real execution.
- The real execution state of workers, the planner and the main agent now drives the task status badge, fixing workers showing "idle" while running.
- Worker sessions keep per-item controls and the current session's token summary, and the model name moved next to the current session title.

#### Removed

- Removed worker multi-select, select-all and bulk pause/resume from the UI, along with the worker bulk-control API and its mock contract.
- Removed the token badge and tooltip from worker list rows; the complete underlying token ledger and the task aggregation API remain.

### LLM

#### Added

- Tasks support an ordered LLM config chain; when a provider quota shortfall is clearly identified it switches to the next config automatically, persisting the current config, exhaustion state and error summary.
- Running and paused tasks can edit the whole config chain, reorder it and switch the current config manually, effective from the next LLM call.
- Automatic switches, manual switches and whole-chain exhaustion are written as structured system activity, with de-duplicated notifications popped through the task activity stream.
- Added a task role model resolution API that resolves the config and model the Main Agent, Planner and Worker will use on their next call.
- Added an optional global LLM Pool with configurable call order, fallback when a specified model fails, health status, cooldown recovery and manual reset.
- Added an always-on LLM usage ledger aggregating input, output and cache tokens by task, session, model and config.

#### Changed

- Goal decomposition, the Planner, Workers and the main agent share a task-level LLM runtime (resolution priority below).
- Failover reacts only to explicit quota, balance or billing errors; ordinary rate limits, authentication, network, server and context errors never cause a wrong switch.
- The LLM config page became a list of config cards with right-hand drawer editing, offering Pool rotation order, priority, exclusions, health status and recovery actions.
- Config-chain exhaustion messages wrap on narrow screens; the current model changed from a session-list icon to a text label with a full tooltip next to the current session title.
- The order in which each in-task role resolves its LLM is now "agent binding -> task config chain -> global": roles explicitly bound to a model always run on it, unbound roles fall to the task chain, and to the global config when the task chain is empty.
- An empty outbound proxy means a direct connection, no longer falling back to the `HTTP_PROXY`/`HTTPS_PROXY` environment variables (an explicit `ARTEX_LLM_PROXY` is unaffected); the proxy input accepts `socks5://user:pass@host:port` with credentials.

#### Fixed

- Transient streaming failures before commit (before any output was produced) are retried with safe backoff on the same provider, markedly reducing "stopped after one or two tools, no summary, terminal state `model_error`"; quota exhaustion, context too long and deterministic 4xx errors are not retried and are still handled by failover and compaction recovery respectively.

#### Removed

- Removed the LLM icon from the session list to avoid confusion with worker status icons.

### UI

#### Added

- Tasks support creating, renaming, deleting and filtering global categories; a category can be chosen directly when creating a task.
- Added global task template CRUD with a right-hand management drawer; the new-task form can load a preset description and goal, or save the current content as a template.
- New tasks can link several source tasks and several company asset scopes; company scope is recognized automatically from a single multi-line text box as domains, URLs, IPs, CIDRs, ICP filings and company keywords.
- Task test assets can be added and removed live, recording their source -- manual, company, inherited or discovered by an agent; the current test assets and a source summary appear next to the worker session title.
- The findings page groups by task with independent paging per group, and supports writing a description for a finding and creating a high-priority deepen intent.
- Conversations can be renamed, pinned, unpinned and deleted; the task list supports bulk pause and resume of the current page.
- Traffic details and tool execution details moved into right-hand drawers; HTTP messages get the `Host` header filled in, with the request line, status code, headers, JSON and markup bodies highlighted.
- The task list's action column gains "Details" and "Pause/Resume" buttons; the conversation send key can be configured in system settings (`Enter` / `Cmd+Enter`, etc.), and the web search section gains a proxy input.
- The badge to the right of the session title now shows the LLM config name, with the model ID moved to a hover tooltip; tasks can have an optional name, and the task list gains a name column and search (falling back to the description when empty).
- The skills page adds usage counts, last-used time and missing-dependency statistics, making it easy to find skills that are not taking effect or not installed.

#### Changed

- Task titles became focusable detail links; task assets, company assets, finding task groups and findings within groups use real server-side paging, stable sorting and exact totals.
- Adding a company uses a right-hand drawer, and scope entry became a single multi-line text field with live recognition, validation and type preview.
- The main agent input auto-grows, sends with `Enter`, adds a newline with `Shift+Enter`, and avoids sending by mistake during CJK input-method composition.
- Agent previews, task reports and related details all use the shared Markdown renderer; delete confirmations, long errors and mobile drawer widths were fixed consistently.
- The task template selector displays and searches by template name and submits the template ID; the system's original font size was restored, and the app version is shown consistently as `0.3.3`.
- The task total and current session tokens highlight only the input, cache-read and output values; the send button uses a simpler up-arrow icon.
- The test scope in the task overview shows company names instead of IDs.

#### Fixed

- Ordinary text containing dots is no longer mistaken for an ICP filing number.
- Fixed variable catalog entries colliding with global runtime variables (such as `{{.Now}}`), which rendered duplicate keys in the agent editor's variable list.

#### Removed

- Removed the separate "Open" button on task cards; clicking the task title opens the details.
- Removed the dashboard's "New task" button, the Logo URL input when adding a company, and the finding-count badges at the top of the findings page and in task groups.
- Reverted the style that enlarged the global font by 10%, and removed the worker checkbox, model icon and per-row token statistics from the session list.

### Agent

#### Added

- New tasks can link several existing tasks directly, inheriting live and read-only the direct source tasks' goals, facts, findings, completed intents, asset scope and blackboard context.
- Blackboard read tools can query source-task nodes, facts, findings and execution traces on demand; inherited nodes carry a source marker and every write tool refuses to modify them.
- Company scope tools support domains, URLs, IPs, CIDRs, ICP filings and company keywords; keywords serve only as scope hints for agents and do not take part in automatic asset ownership.
- Deepening a finding creates a high-priority manual worker intent in the original task, with asset anchors and a `derived_from` edge.
- The overview gains a "Goal management" card for viewing, adding, editing and deleting goals manually; adding or editing notifies the Planner and revives the task, while deleting hard-deletes the goal node (cascading to its edges and anchors) without reviving it.
- The main agent gets the `steer_work` tool by default, injecting course corrections into a running worker live without interrupting it or losing progress (still checking that the intent belongs to this task).

#### Changed

- Source-task intents do not enter the new task's frontier; the new task keeps its own exploration, execution queue, working directory and conversation history.
- Deleting a running intent no longer destroys data: it stops at `stopped`, requires a deletion reason, attaches the reason to the intent as a fact and writes it into the payload, and the planner perceives it through a `cancelled` trigger (keeping the intent content and reason).
- Main agent conversations are now driven by the server-side activity stream, and failed sends can restore the input; opening a session scrolls to the bottom automatically and keeps the last reply visible after details lazy-load.
- Pausing a task terminates the current Main Agent, Planner and Worker calls, but does not prevent the user from starting a new main agent orchestration session during the pause.
- Cancellation, closing and stream interruption all keep the real termination reason, generated content, rounds run, duration, tokens and unreturned tool calls.

#### Removed

- Removed the main agent client's optimistic message echo, avoiding duplicate messages and cross-session bleed under pauses, failures or concurrent activity.

### Constraints

#### Added

- Goal decomposition first extracts operating constraints (allow/deny) and then decomposes goals, and the main agent can add more at runtime; constraints are injected into the Planner and Worker system prompts with top priority, and de-biased diversity and broadening exploration explicitly obey them.
- The overview gains a "Constraint management" card with create/update/delete APIs; constraint injection can be toggled separately for the Planner / Worker (both on by default, read every round, effective immediately). The new `task_constraints` table uses `CREATE TABLE IF NOT EXISTS`, so old databases get it automatically.

### Interception

#### Added

- Beyond regex/string rules, command interception gains model fallback approval: when no rule matches, a model makes an `ALLOW`/`ASK`/`DENY` semantic decision, with configurable failure fallback and approval-timeout actions; the interception page splits into "Interception rules / Model config" tabs, and model decisions are labeled with a model prefix and a reason (written as a Chinese tag in this release, "[Model]" in later releases).

#### Fixed

- Hardened judge output parsing so a correct `DENY` decision is never mistaken for an allow.

### Traffic

#### Changed

- Traffic recording now stores each whole exchange in SQLite (large bodies overflow into a hash-de-duplicated blob bucket), with a trigram full-text index on text bodies supporting arbitrary-substring and CJK search; deletion becomes a single SQL transaction, dropping from hours to milliseconds without pausing recording meanwhile. Added streaming download of large bodies and full-text parameters for `traffic_search`; old file-tree data needs no migration and remains readable, searchable and deletable.

### Tasks and assets

#### Added

- Task creation gains an "Asset coverage feature" switch (on by default): when off, coverage is neither computed nor shown, the situation graph shows only assets, `task_scope` does not accumulate automatically, and the related tools are removed from the Planner / main agent; company links are unaffected by this switch.
- `insert_assets` gains a per-asset `related` flag (default `true`): it takes effect only with coverage on, and `false` stores the asset only in the shared asset store without counting toward this task's coverage (e.g. neighboring sites or unrelated assets discovered along the way).
- Company scope and task test assets uniformly recognize domains, URLs, IPs, CIDRs, ICP filings and keyword text; domains/IPs can create or reuse global assets, while CIDRs/ICP filings/keywords are kept as task scope context.

### Build

- `build.sh --release` builds Linux amd64/arm64, macOS amd64/arm64 and Windows amd64 in one go, producing zip release packages with `skills/`, config examples and the README.
- The Go linker strips debug information and zip release packages are produced; UPX became explicitly optional, avoiding segmentation faults when its self-extracting ELF starts on some Linux environments.
- The release workflow runs a startup smoke test on the Linux amd64 binary and ships `SHA256SUMS` with the release packages.

### Contributors

- [@neouks](https://github.com/neouks)

## [0.3.2] - 2026-08-20

### Added

- New tasks can link several existing tasks, inheriting live and read-only the direct source tasks' facts, findings, completed intents, asset scope and blackboard context; the new task still uses its own execution queue, working directory and session history.
- Tasks support an ordered LLM config chain. When a provider quota shortfall is clearly identified it switches to the next config automatically, persisting the current config, exhaustion state and structured audit activity.
- Running and paused tasks can edit the LLM config chain, reorder it and switch the current config manually; automatic switches, manual switches and whole-chain exhaustion are announced on the task detail page.
- Running workers can be paused, resumed and cancelled. Pausing keeps blackboard data, while cancelling transactionally cleans up the intent and the facts, findings and execution records it produced directly, after the worker stops writing.
- Deleting a task can optionally also clean up linked assets, traffic, findings and the task's files on disk, with a deletion barrier, concurrency protection and auditable deletion statistics.
- Added an optional task concurrency limit; new tasks over the limit queue FIFO and start automatically once a run slot is freed.
- Added mock contracts for task asset paging, company asset paging, task category statistics and paged intents.
- Added the `build.sh` single-binary build script, supporting static front-end export, resource embedding, cross-platform targets and build version injection.

### Changed

- An explicit task-level LLM config chain coexists with the existing global LLM Pool; the explicit chain keeps strict quota-failover semantics, and without one the agent-binding and global config rules apply as before.
- The main agent input supports auto-growing multi-line input, `Enter` to send, `Shift+Enter` for a newline, and avoids sending by mistake during CJK input-method composition.
- The Planner, Workers and main agent share a task-level LLM runtime; the task chain uses the smallest context window among its candidate models as a safe compaction threshold.
- The task detail page shows running, idle and paused states from real LLM call state; source-task facts, findings, intents, asset references and graph nodes are uniformly marked with their source and kept read-only.
- Agent previews, task reports and related detail views all use the shared Markdown rendering component.
- LLM model configs use cards and drawer interactions, with the model list scrolling independently inside the drawer.
- Task pause no longer blocks main agent conversations: main agent orchestration sessions are independent of task pause, and new messages can still be sent while paused (pause only terminates the round currently in progress).
- The default wall-clock duration of a single worker run changed from 600 to 1200 seconds.

### Fixed

- Removed the main agent console's optimistic echo in favor of pure server-side rendering, fixing messages getting mixed up or bleeding in content from other sessions when pausing or when sending fails.
- Opening a main agent session scrolls to the bottom by default and shows the last reply in full: after the last reply's full content lazy-loads it sticks to the bottom automatically instead of being pushed off screen.
- Fixed the main agent session continuing to run after the task was paused, and the main agent not being stopped when an orchestration agent paused the task.
- Fixed the task status badge and action buttons going out of sync with whether the task completed or the Planner, Worker or main agent was actually running.
- Fixed possible late blackboard writes or leftover files between worker cancellation, task deletion and concurrent writes.
- Fixed broken Markdown previews, long text overflowing delete confirmations, mobile widths and some misaligned task detail buttons.
- Added named termination reasons to every agent cancellation path; activity details show who cancelled, the terminal state, rounds run, duration, token usage and unreturned tool calls.
- Fixed a race where the parent context could overwrite the named `shutdown` reason first when the backend shut down, and Chinese activity summaries being truncated by bytes and producing garbled text.
- Fixed cancellation events with partial streamed output losing their real termination reason, while keeping the content generated before cancellation.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

[Unreleased]: https://github.com/Autumn-27/ARTEX/compare/v0.3.10...HEAD
[0.3.10]: https://github.com/Autumn-27/ARTEX/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/Autumn-27/ARTEX/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/Autumn-27/ARTEX/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/Autumn-27/ARTEX/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/Autumn-27/ARTEX/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/Autumn-27/ARTEX/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/Autumn-27/ARTEX/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Autumn-27/ARTEX/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Autumn-27/ARTEX/compare/v0.3.1...v0.3.2
