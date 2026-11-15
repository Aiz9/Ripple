# Controlled Android assessment engine

## Source reconnaissance (2026-10-21)

Inspected the current Go net/http server, Next.js interface, PostgreSQL JSONB assessment store, runtime queue, APK analyzer, Frida runner, API checker, encrypted account/artifact storage, checklist, finding validation and reporting. The inherited general-purpose agent engine is separate from the controlled Android dispatcher. No stack migration is needed.

Verified upstream source through GitHub raw files (network DNS prevented a local clone):

| ARTEX concept and source | Existing equivalent | Adaptation |
|---|---|---|
| [Goal decomposition](https://github.com/jiwoochris/artex-global/blob/main/agent/goals.go) | Objective coverage in assessment/planner.go | Persistent explicit criteria and evidence-linked goal evaluation |
| [Planner](https://github.com/jiwoochris/artex-global/blob/main/agent/planner.go) | Deterministic Replan plus read-only LLM advice | Typed, prerequisite-driven intents; no LLM required |
| [Single-intent worker](https://github.com/jiwoochris/artex-global/blob/main/agent/worker.go) | APK, runtime, API adapters | Reuse bounded adapters, without shell command generation |
| [Scheduler](https://github.com/jiwoochris/artex-global/blob/main/server/engine.go) | PostgreSQL runtime queue | Durable deduplicated wakeups, leases, fenced completion and cancellation |
| [Asset store](https://github.com/jiwoochris/artex-global/blob/main/db/assets.go) | APK inventory and assessment endpoints | Build-hash identity; assessment-scoped evidence links |
| [Exploration graph and claims](https://github.com/jiwoochris/artex-global/blob/main/db/exploration.go) | Evidence, findings and execution records | Append-only provenance relationships and goal history |
| [Trace tools](https://github.com/jiwoochris/artex-global/blob/main/agent/tools.go) | Audit and execution summaries | Assessment-scoped searchable worker steps |
| Goal judgement and reporting | Reviewed evidence, FinalReport, Markdown report | Keep unresolved work visible and retain manual review gates |

Upstream Plan constructs a ToolSet, loads graph context and invokes an LLM. Its engine debounces changes; ClaimIntent uses a conditional state update. The asset store also accepts authentication metadata, which this implementation must not copy into graphs. Trace retrieval verifies intent ownership and supports step selection. These are architectural references, not interchangeable Android APIs.

The controlled application's existing JSONB document is its aggregate boundary. Goals, intents and exploration records belong inside that aggregate so evidence and transitions commit together under its existing row lock. Queue notifications and reusable build identities use relational tables. This avoids a second inconsistent copy of findings/checklist state and does not introduce infrastructure.

## Implemented execution model

The existing Go/PostgreSQL/Next.js stack remains. `internal/assessment/engine.go` owns deterministic planning, typed intents, capability checks, dependencies, bounded retries, fencing tokens and leases. Assessment creation now includes nine child goals and an aggregate goal. Goal criteria examine current evidence independently of job success.

`android_assessments.document.engine` persists goals, intents, facts, adapter traces, append-only graph relationships, goal evaluations and checklist transitions. Existing findings, sources, credentials and checklist records remain authoritative. `android_engine_events` is a coalescing transactional outbox; an update trigger wakes relevant assessments. Claims lock the assessment with `FOR UPDATE SKIP LOCKED`, commit before execution, and merge results under the existing row lock. Independent local operations run outside that lock. Evidence updates and intent completion commit together. Lease tokens reject late results after recovery. Pure local work can retry; device/network work is not automatically replayed after an uncertain outcome.

The relational `android_build_identities` and `android_assessment_builds` tables share only SHA-256 build identity. Graph/evidence reads are restricted to the requested assessment. Package names do not merge builds. Authentication remains the application's existing single-operator JWT boundary; this change does not add a multi-tenant identity system.

Nine handler types share one engine:

| Handler | Operation and limit |
|---|---|
| APK static | Real existing hash/manifest/profile analysis and bounded URL extraction |
| Runtime | Dispatches the existing PostgreSQL ADB/Frida job; selected device and runtime policy required |
| API discovery | Reconciles source-backed inventory already populated by APK/runtime/import adapters |
| API security | Dispatches existing predefined API checks after observed safe-method discovery, explicit URL scope and active-test authorization |
| Storage | Evaluates collected procedure-specific storage evidence; runtime adapter supplies supported device observations |
| Platform | Evaluates collected exported-component/deep-link/WebView evidence |
| Checklist | Evaluates all existing procedures using their evidence; never converts a marker into a pass |
| Validation | Checks existing evidence-backed reviewed dispositions; unresolved candidates remain blocked for review |
| Reporting | Generates the existing Markdown report, with goal status, evidence and limitations |

Storage/platform handlers do not add arbitrary filesystem extraction or component exploitation. Validation does not autonomously invent or execute an exploit. Missing capabilities are explicit limitations, not simulated successes. Trace steps are adapter-level operations; they do not record each Frida hook or internal library call individually.

The engine is enabled from the new **Assessment engine** tab. Existing runtime/API/dispatch interfaces remain available. Starting the engine does not authorize new devices, targets, or automatic login. The planner can be used without an LLM. Free-text restrictions block automatic runtime/API scheduling because the deterministic layer cannot establish their meaning safely.

## Persistence and configuration

The idempotent migration is appended to `internal/db/schema.sql`, applied by the existing startup migration mechanism and advisory lock. It adds three tables, an event due-time index and the `android_engine_notify` trigger/function. Existing assessment JSON receives additive fields; no evidence or credential table is replaced. Migration and reopen tests ran on isolated PostgreSQL 16.

Per-assessment limits are validated through `POST .../engine/start` with an optional `limits` object:

```json
{"limits":{"workers":4,"tool_seconds":120,"max_intents":500,"worker_retries":2,"observation_seconds":60}}
```

Allowed ranges are 1–16 workers, 10–300 seconds for local tools, 10–2000 intents, 0–5 local-worker retries, and 30–300 observation seconds. Runtime/API adapters retain their existing bounded job and request timeouts, budgets and device reservations. The deterministic planner has no LLM retry loop; database availability is retried by the bounded polling loop. There is no separately configurable planner-failure retry budget.

Cancellation is terminal for that engine run: it stops new claims, invalidates local claim tokens and pauses assessment policy. Runtime jobs observe that pause through their existing cancellation monitor. A local bounded file inspection can finish computing, but cannot commit after cancellation. Create a new assessment/retest for a cancelled run.

## API additions

All paths below are under `/api/android/assessments/{aid}` and use existing authentication:

- `GET /engine`, `/engine/goals`, `/engine/intents`, `/engine/blocked`.
- `GET /engine/graph`: assessment-owned nodes and provenance edges.
- `GET /engine/traces?q=...&intent_id=...&step_ids=...`: list, search or select trace steps.
- `POST /engine/start`, `/engine/replan`, `/engine/cancel` (JSON body `{}` when no options).
- `POST /retests`: `{"asset_id":"original-asset-id","apk_id":"uploaded-new-sha256"}`.
- `GET /retest-comparison`: reviewed outcome comparison against the linked original assessment.

A retest creates a distinct assessment/build, retains original subject associations for comparison, and carries previous findings as unvalidated hypotheses. Original evidence and credentials are not copied or overwritten. No finding absence is treated as remediation. New reviewed evidence must match the property, role, parameters, environment and new revision. Configure the new assessment's device, authorization and accounts separately.

## Changed files

New:

- `internal/assessment/engine.go`, `internal/assessment/engine_graph.go`, `internal/assessment/retest.go`, `internal/assessment/engine_test.go`.
- `internal/db/android_engine.go`, `internal/db/android_engine_test.go`.
- `internal/server/android_engine.go`, `internal/server/android_retest.go`, `internal/server/android_engine_test.go`, `internal/server/android_engine_postgres_test.go`.
- `web/src/components/assessment-engine.tsx`.
- `docs/AUTONOMOUS_ENGINE.md`, `docs/ASSESSMENT_WORKFLOW.md`, `docs/ENGINE_VERIFICATION.md`.

Modified:

- `internal/assessment/model.go`, `internal/assessment/planner.go`, `internal/assessment/report.go`, `internal/assessment/mobile.go`, `internal/assessment/import.go`, `internal/assessment/discovered_scope_test.go`.
- `internal/db/schema.sql`, `internal/db/assessments.go`.
- `internal/server/server.go`, `internal/server/assessments.go`, `internal/server/assessment_dispatch.go`, `internal/server/assessment_api_agent.go`, `internal/server/assessment_secrets.go`, `internal/server/assessment_test.go`.
- `internal/apicheck/check_test.go` (fixtures now explicitly authorize test targets).
- `web/src/app/(main)/android/assessments/page.tsx`, `web/src/components/android-runtime.tsx`, `web/src/lib/assessment-api.ts`.

The previously implemented APK account form and 91-procedure checklist remain. Short credential values no longer break generated provenance IDs during engine redaction. Existing dispatch result merging now preserves evidence committed concurrently by another worker. Reports redact stored test credentials before export.

## Start and test

From `ARTEX/Android`, configure the existing database through `ANDROIDLAB_PG_DSN` or the existing configuration file. Keep its identity/encryption key stable across restarts. No new infrastructure service is required.

```bash
# Development backend and frontend (separate terminals)
go run ./cmd/artex -addr :8797
cd web && npm run dev

# Existing bundled build/start workflow
./build-android.sh
./run-android.sh

# Webpack alternative used during verification
cd web
NEXT_EXPORT=1 npx next build --webpack
cd ..
cp -a web/out/. server/webui/dist/
go build -tags embedui -o androidlab ./cmd/artex
```

```bash
# Deterministic checks and existing Android regression tests
go test ./internal/assessment ./internal/androidapk ./internal/androidruntime ./internal/apicheck

# Engine, accounts, route authentication, merge and offline demonstration
go test ./internal/server -run 'TestEngine|TestAPKAccount|TestAssessmentCredential|TestAssessmentLegacy|TestAssessmentAPK'

# Use an ISOLATED database; these tests write fixtures and apply migrations.
export ANDROIDLAB_TEST_PG_DSN='postgres://test-user:test-password@127.0.0.1:5432/test-db?sslmode=disable'
go test ./internal/db -run TestEnginePostgres -count=1 -v
go test ./internal/server -run 'TestEngineHTTPPostgres|TestAssessmentHTTPPostgres|TestAPIAgentHTTPPostgres|TestDynamicWorkflowPostgres|TestAssessmentAPKOnlyHTTPPostgres' -count=1 -v

# Full repository suite also uses ANDROIDLAB_PG_DSN; point it ONLY at a test DB.
ANDROIDLAB_PG_DSN="$ANDROIDLAB_TEST_PG_DSN" go test -p 1 ./...
```

See `ENGINE_VERIFICATION.md` for actual results and unresolved failures; the full repository suite is not claimed green.
