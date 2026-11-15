# `/btw` testing guide

Side-question verification focuses on context isolation, budget, concurrency, recovery and UI behavior. Tests use a disposable PostgreSQL database and controlled model fixtures; database cases need `ANDROIDLAB_PG_DSN` set, and it must never point at a production database.

## Engineering checks

| Area | Representative cases |
| --- | --- |
| Structured message deep copy and complete snapshot boundaries | `TestCheckpointDeepCopyAndBoundaries` |
| Excluding half-finished replies and keeping the actual model-pool member | `TestSnapshotExcludesPartialStreamAndSelectsPoolMember` |
| Tool pairing, replay trimming and input budget | `TestBuildRequestCompactionToolPairingAndBudget` |
| Main/side concurrency and two-way cancellation isolation | `TestMainSideConcurrencyAndIndependentCancellation` |
| No tool execution, and usage saved on failure | `TestServiceNoToolsAndUsageOnFailure` |
| 20-pair boundary, restart and summary recovery | `TestSideTwentyExchangeBoundaryAndRestart` |
| Content-based budget estimation and long-context chunking | `TestSideBudgetCountsContentNotJSONCharacters`, `TestSideLongExchangeAndSnapshotCompactionAreBounded` |
| Single overflow recovery, failure usage and stopping without reduction | `TestSideOverflowRecoveryOnceAndFailureUsage`, `TestSideOverflowWithoutReductionDoesNotRepeatAnswer` |
| Summary cancellation, failure, call limit and small windows | `TestSideSummaryCancellationAndFailureDoNotAdvanceMemory`, `TestSideSummaryCallCapAndStaticBudget`, `TestSideTwentyLongRepliesRespectSmallWindow` |
| History paging, idempotency, restart and late writes | database side-question tests |
| Authentication, parent-resource ownership, global concurrency and SSE | service API side-question tests |
| Task archive, restore and old-format compatibility | `TestSideTaskArchiveVersions` |

Core regression:

```sh
go test -race ./internal/sidequestion -count=1
```

With a separate test database configured, run the isolation and archive cases of the related packages:

```sh
go test -race ./internal/agent ./internal/db ./internal/server ./internal/sidequestion ./internal/llmrec ./internal/llmpool \
  -run 'Test(Side|Checkpoint|Snapshot|BuildRequest|Service|MainSide|CaptureRun|TaskArchive|CompleteForwards|StopIntent|CancelIntent)' -count=1
```

Front-end checks run in the `web` directory:

```sh
npx tsc --noEmit
npx biome check src/lib/side-questions.ts src/hooks/use-side-questions.ts src/components/side-question-workspace.tsx
npm run build
```

## UI checks

Check both the desktop and narrow-screen layouts:

- Submit `/btw` while the main session is running; the main content keeps updating and the side question displays independently.
- Consecutive follow-ups and stop; stopping a side question does not cancel the main task, and existing answers are kept.
- History and current state recover after closing the panel, refreshing and SSE reconnection.
- Histories of regular chat, the task MainAgent and different workers are isolated from each other.
- After confirming clear, only side history is deleted, the main snapshot is kept, and late results cannot restore cleared data.
- Long questions, long answers, the summary stage and draft recovery after failure all behave correctly with no horizontal overflow.

## External model compatibility

To verify an external provider, use a dedicated test config and synthetic context, and check streaming, non-streaming, cancellation and the usage response. When an endpoint returns no usage, the recorded zero usage must not be read as "not billed". Answer-quality checks cannot replace the concurrency, tool-isolation and persistence assertions.

This guide describes how to reproduce; it does not claim the full suite has passed. Existing failures in cleanup timing, graph scope and norma cases must be recorded as actually observed; a passing targeted side-question run is no substitute for full acceptance.
