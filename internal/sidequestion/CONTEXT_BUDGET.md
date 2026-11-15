# Long side conversations and the context budget

The original implementation treated the character count of the request JSON directly as tokens and inherited the main task's 32K output reserve, so it rejected normal side questions early when there was a lot of HTML, JS or tool output.

## Review of open-source implementations

- [Grok CLI side context](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/agent.ts#L739): takes excerpts from recent user and assistant text with a character budget of about 2000, truncating each item to at most 400 characters. It keeps no continuous side Q&A history on this path.
- [Grok CLI standalone request](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/utils/side-question.ts): separate cancellation signal; output limited to 2048 tokens when the model supports it; no tools.
- [Grok CLI main-session compaction](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/compaction.ts): estimates tokens, keeps recent content, folds new content into the previous summary, and handles truncation across turns.
- [OpenCode session compaction](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/compaction.ts): whole-request estimation, output/buffer reserves, recent content plus a rolling summary, summary requests without tools; it defaults to a recent budget of 8000 and a summary output limit of 4096 tokens.
- [OpenCode overflow recovery](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/runner/llm.ts): attempts overflow recovery only before the assistant has started producing output, and the recovered call never re-enters the same recovery path.

ARTEX adopts the separate output budget, recent content plus rolling summary, and bounded recovery. It keeps norma v0.3.6's structured messages and tool pairing instead of copying Grok's text excerpts, and does not write OpenCode-style main-session compaction events into the ARTEX main transcript.

## Request budget and execution

- Messages use norma's per-content-block UTF-8 byte estimate with a 4/3 margin, additionally counting the system prompt, tool schemas and message envelope overhead. The estimate is not an exact model token count.
- Side output defaults to at most 8192 tokens and never exceeds the output limit set in the main config. The service environment variable `ANDROIDLAB_BTW_MAX_OUTPUT_TOKENS` sets a limit between 256 and 32768; it never changes the product's default model or main task parameters.
- The input budget is the context window minus the output limit and a safety margin; an unknown window uses the platform default of 200K. The safety margin is 5% of the window, at least 128 and at most 8192 tokens.
- Successful Q&A pairs are loaded in increasing ordinal order, at most 20 per batch. At most 20 pairs are kept verbatim, with a token budget of at most 1/4 of the input budget and no more than 16K.
- Excess pairs are folded into the rolling summary. Summaries carry their history source and context time; past assistant answers are not equivalent to new tool evidence, and the latest main snapshot wins on conflict.
- When the main context is still too long, only old messages in the copy are summarized, keeping at most 8K tokens of recent content; the cut point never separates a tool call from its result. An oversized single pair goes into the summary as a whole.
- Summary input is chunked UTF-8-safely according to the actual remaining window, with a 2048-token output limit; empty summaries, truncation, tool calls or exceeding the summary budget are never cached. A single side question makes at most 12 summary calls under the same 120-second timeout; reaching the limit fails explicitly instead of looping forever.
- If the model's first response reports a context overflow before producing any text or tool calls, the input is reduced further and retried at most once; if the estimated size does not shrink, recovery stops immediately. Other model errors and partial streamed output do not trigger this recovery.
- All usage obtained -- including summaries, failed attempts and usage at cancellation -- is added to the same side request. When the provider returns no usage, zero is recorded; an estimate is never passed off as actual usage.

## Persistence and UI

`side_question_sessions.memory` stores the summary of old Q&A, the ordinals it covers, and the main-context summary cached by snapshot identity. `side_question_requests.context_info` stores the preparation stage, the number of pairs actually replayed, summary usage and the budget estimate.

A summary is saved only while the original request is still running and the clear version matches; clear also wipes the cache, and late writes never restore cleared data. A new snapshot never reuses an old snapshot's summary. Summary fields are saved with v3 task archives; restoring an older v3 archive missing these fields fills in empty objects, and v1/v2 remain compatible.

POST accepts and returns the request first; preparation and compaction run in the background without holding the admission lock or a database transaction. SSE/history show the preparing, organizing Q&A, compacting copy and answering stages; a compaction failure is saved as that side request's failed terminal state. The front end keeps the error and restores the failed question as a draft instead of covering the input with a toast; history polling no longer clears submit errors.

## Test coverage and reproduction

Regression coverage of the context budget includes:

- Replay boundaries, summary retention and cache reuse at 19/20/21/50 Q&A pairs.
- Long Chinese answers, structured tool pairing, summary chunk budgets and snapshot isolation.
- Summary failure, cancellation, truncation, invalid responses and the call limit.
- Single recovery after a context overflow, stopping when the input does not shrink, and no retry after partial output.
- Clear and late writes, persistence recovery and archive compatibility.

The cases live in [context_test.go](context_test.go), [sidequestion_test.go](sidequestion_test.go) and the database and service API tests. Reproduction commands and UI checks are in the [testing guide](VALIDATION.md).
