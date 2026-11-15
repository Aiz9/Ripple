# Implementation follow-up — 2026-10-22

Acceptance baseline: [completion audit](COMPLETION_CHECKLIST.md). Work is in progress; full acceptance remains **REJECT**.

## Phase 1: regression baseline

The initial full run used PostgreSQL 16 in an isolated container and `go test -json -p 1 -count=1 ./...`. Raw output: `/tmp/ripple-phase1-full.jsonl` (temporary local artifact).

The Android tree is untracked inside the parent repository, so a clean before/after implementation commit is unavailable. Inspection of parent commit `5ef825d` confirms Chinese test expectations inherited from that version; the current application emits English messages. This is a source comparison, not a successful execution of the original baseline.

Root causes addressed so far:

- Missing task/company scope in the inherited graph overview: restored scope expansion, preserving configured display values and coverage-disabled behavior.
- Test assertions retained pre-translation wording. Updated exact required-field/provenance/workflow assertions to English equivalents, retaining status, count, evidence and policy assertions.
- Legacy route fixtures ran with legacy execution disabled. Test-process configuration now explicitly enables their required mode; the controlled boundary test explicitly disables it. Deployment defaults remain disabled.
- Company-scope fixture left its company/CIDR behind. Cleanup now removes the owned company.
- Synchronous route fixtures started unrelated recovered tasks and left file-writing goroutines active during cleanup. Those fixtures now use a cancelled service context, as the existing traffic-evidence route fixture does.

Reproducible database runner: `GOCACHE=/tmp/ripple-go-cache scripts/test-postgres.sh -json ./...`. It creates a private container/database and removes the container on exit. It never uses the existing application database. Docker is required.

### Initial failing tests (including failing subtests)

- `internal/agent/TestGraphOverviewExpandsAssociatedCompanyScope`
- `internal/agent/TestReportFindingAtomicContract`
- `internal/db/TestCreateTaskWithCompanyScopes`
- `internal/notify/TestChannelValidateReportsMissingFields`
- `internal/server/TestChatMentionConversationReceivesServerDetails`
- `internal/server/TestCoreTaskLifecyclePG`
- `internal/server/TestRetestHTTPThroughConversationAndTools`
- `internal/server/TestRetestStopsFailuresAndNoVerdict/stop`
- `internal/server/TestRetestStopsFailuresAndNoVerdict/failure`
- `internal/server/TestRetestStopsFailuresAndNoVerdict/no_verdict`
- `internal/server/TestRetestStopsFailuresAndNoVerdict`
- `internal/server/TestRetestFixedUpdatesFindingThroughConversation`
- `internal/server/TestFindingWorkflowAutoHintToPlannerAndSetting`
- `internal/server/TestFindingWorkflowMigrationPreservesUserConfiguration`
- `internal/server/TestFindingWorkflowReporterBindsBeforeWritingReport`
- `internal/server/TestInterceptDetailHTTP`
- `internal/server/TestJudgeRetrySettingsAndFallbackHTTP`
- `internal/server/TestNotifyEndToEndRealtimeDelivery`
- `internal/server/TestNotifyChannelAPICreateValidation/invalid_kind`
- `internal/server/TestNotifyChannelAPICreateValidation/missing_name`
- `internal/server/TestNotifyChannelAPICreateValidation/missing_webhook`
- `internal/server/TestNotifyChannelAPICreateValidation/webhook_invalid_scheme`
- `internal/server/TestNotifyChannelAPICreateValidation/invalid_mode`
- `internal/server/TestNotifyChannelAPICreateValidation`
- `internal/server/TestSideHTTPPreparationCancellationAndClear/false`
- `internal/server/TestSideHTTPPreparationCancellationAndClear/true`
- `internal/server/TestSideHTTPPreparationCancellationAndClear`
- `internal/server/TestSideHTTPBusyIsolationClearAndReconnect`
- `internal/server/TestSideHTTPGlobalLimitTaskWorkerAndDeletion`
- `internal/server/TestSideCheckpointPersistsBeforeAdmissionAndRestart`
- `internal/server/TestSideTaskDrainPersistsBeforeArchive`
- `internal/server/TestTaskArchiveAPIQueueListAndLimits`
- `internal/server/TestTaskCategoryBatchRoute`
- `internal/server/TestWorkerControlRoutes`
- `internal/server/TestTaskMetadataPatchReturnsRenameAndPin`
- `internal/server/TestConversationBatchDeleteReportsMissing`
- `internal/server/TestConversationPatchReturnsPinState`

### Initial skipped tests

- `internal/androidapk/TestDifferentialExport`
- `internal/apicheck/TestIndependentZAPFixture`
- `internal/server/TestLiveContextReview`

## Live environment

`adb devices -l` returned no attached device. Live Android installation/launch, installed hash comparison, Genymotion, Frida, capture, and disconnect/recovery are **BLOCKED** pending an authorized connected device. Mocks do not satisfy those checks.

## Codebase review — 2026-10-23

Fixed subprocess output limits in `androidapk` and `androidruntime`. Embedding
`bytes.Buffer` exposed `ReadFrom`, allowing `io.Copy` to bypass the bounded
`Write` method. Both buffers now use composition. Regression tests reproduced
the bypass before the fix and cover below-limit, exact-limit and oversized
streams. Runtime capture still drains output and records truncation; APK parsing
rejects excessive output.

Fixed assessment report export accepting `draft=1` but rejecting `draft=true`.
Boolean values are parsed explicitly, invalid values return HTTP 400, and false
values retain final-report validation. Database-backed tests cover these cases.

Fixed retry-delay overflow in the bundled Norma LLM client by capping the
attempt before shifting. Large retry counts retain the eight-second delay.
The retry fixture now supplies the HTTP client normally initialized by the
provider constructor. Added `npm test` and `npm run typecheck` scripts.

Fresh verification:

- Root suite, disposable PostgreSQL: **PASS**, 21 packages; 1,098 test/subtest
  passes and three optional skips (`TestDifferentialExport`,
  `TestIndependentZAPFixture`, `TestLiveContextReview`). Three additional
  packages contain no tests. Command: `GOCACHE=/tmp/ripple-go-cache scripts/test-postgres.sh -json ./...`.
- Root `go vet ./...`: **PASS**.
- Race checks for assessment/APK/runtime/API packages and bundled `norma/llm`:
  **PASS**.
- Frontend unit tests: **PASS**, eight tests. TypeScript: **PASS**.
  Production build: **PASS**, 35 pages generated.
- Frontend lint: **FAIL**, 83 errors, 147 warnings and 915 informational
  diagnostics. Includes accessibility, empty catches and unhandled promises.
- Separate `cd norma && go test ./...`: **FAIL**, seven top-level tests in
  `noa`/`noaadapter`: adaptive growth, suppression release, mostly-competent
  model bounds, long-session bounds, partially compliant model bounds,
  overflow learning and the outdated tier-two limitation assertion. Other
  bundled packages pass. Root `go test ./...` excludes this nested module.

Temporary logs: `/tmp/ripple-review-tests-final.jsonl`,
`/tmp/ripple-review-norma-final.log`, `/tmp/ripple-review-lint-full.log`, and
`/tmp/ripple-review-build.log`. No live-device or external-provider validation
was performed in this review. The root regression suite is now green; this does
not supersede unresolved full-acceptance items or the nested-module failures.

## Lint and compaction follow-up — 2026-10-23

The 83 frontend lint errors and seven reported Norma compaction failures above
are resolved. Frontend labels now target unique control IDs; skill-tree actions
and MCP editing use keyboard-accessible buttons; request failures are surfaced
instead of silently caught. Intentionally triggered refresh, pagination and
scroll effects retain documented dependency exceptions. Lint rules remain enabled.

Small-window compaction pacing now scales down while preserving the established
128K-and-larger behavior. Provider-reported overflow limits reach reactive
recovery. Session defaults resolve the window before deriving pacing settings.
The obsolete test expecting tier-two consolidation to fail now verifies success.
More frequent consolidation exposed a translation-dependent archive assertion;
it now verifies every actual child archive path instead of a translated heading.

Verification:

- Frontend lint: **PASS, zero errors**; 147 existing warnings remain.
- Frontend unit tests: **PASS**, eight tests; TypeScript and production build:
  **PASS**, 35 pages generated.
- Headless Chrome with intercepted fixture APIs: **PASS** for keyboard MCP
  editing, named checkbox toggling, skill/folder/file keyboard actions, label
  targets and absence of page exceptions. No real backend mutations.
- Complete bundled Norma suite: **PASS**. Compaction `go vet`: **PASS**.
- Focused race checks for the repaired compaction, overflow, archive and
  default-window behaviors: **PASS**. The tier-one archive preservation test
  also passed three consecutive race-enabled runs. It now verifies inactive
  retained archives as well as active ones, so consolidation cannot make the
  check vacuous. The unrestricted race suite hit its default ten-minute timeout;
  it is not reported as passing.
- Root disposable-PostgreSQL suite: **PASS**, 21 packages and 1,098 test/subtest
  passes, with the same three optional skips. An initial attempt exhausted the
  temporary filesystem quota; the successful rerun used workspace compiler
  temporary storage.

Temporary logs: `/tmp/ripple-ui-lint-final.log`,
`/tmp/ripple-norma-final-pass2.log`, `/tmp/ripple-compaction-focused-race.log`,
`/tmp/ripple-lint-fix-build.log`, and
`/tmp/ripple-final-root-regression2.jsonl`. Browser fixture script:
`/tmp/ripple-ui-accessibility.mjs`. These results supersede the lint and
nested-module failures in the preceding review, not the broader live-device
acceptance limitations.

## Foreground session lifecycle — 2026-10-23

`run-android.sh`, `start.sh`, `dev.sh`, and `run-docker.sh` now run foreground
sessions without restart loops. The native session owns the configured isolated
`android-lab-pg` database, its backend/frontend process groups and a private ADB
server. The database's restart policy is now `no`. Terminal hangup, Ctrl-C,
termination, startup failure or a dependency exit triggers cleanup. Additional
dedicated containers can be explicitly managed; external/shared services are
not stopped. A session lock prevents duplicate launches from taking resources.

The backend cancels Android work and waits for evidence/archive completion
before closing PostgreSQL. Docker services have automatic restart disabled,
the backend runs directly with an init process, and the foreground Compose
launcher stops services while preserving volumes. Credentials, assessment data,
uploaded APKs and identity keys remain available on the next launch.

Verification: eight launcher regressions passed, covering termination signals,
startup cancellation/failure, descendants left by exiting parents, shutdown
ordering, duplicate launches and external database isolation. Targeted Go
shutdown/assessment/archive integration checks passed with isolated PostgreSQL;
shutdown race checks and Go vet passed. The embedded executable was rebuilt.

Real native launch/close/reopen passed for hangup and termination, preserving
all three existing assessments and the JWT identity. The development frontend
and backend were opened and then stopped with Ctrl-C; no owned descendants or
listeners remained. A disposable Compose project ran the rebuilt backend and
PostgreSQL through two open/close cycles, retaining a test row across cycles;
its containers, network and test volumes were then removed. A complete rebuild
of the large Docker runtime image was not performed.

The installed `Ripple Android` desktop entry opens the managed terminal. Final
checks left `android-lab-pg` stopped and ports 8797, 8798 and 3001 closed.
Unrelated containers, shared ADB, Burp, Genymotion and VPN services were not
stopped by the session tests. The audit database was left outside session
ownership because it is not the configured application database.

Live verification scripts/logs are under ignored `data/session/`; integration
logs are `/tmp/ripple-session-regression.log` and `/tmp/ripple-session-build.log`.
