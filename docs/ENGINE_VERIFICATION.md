# Engine verification — 2026-10-21

## Passing checks

- Executed tests in `assessment`, `androidapk`, `androidruntime`, and `apicheck` passed, including a race-detector run. Two optional external-fixture checks were skipped (see the completion audit). These include scope, evidence applicability, checklist and candidate-validation regressions as well as new engine tests.
- The targeted server/database run passed with the race detector: engine handlers, APK accounts, credential redaction, authenticated routes, concurrent evidence merging, APK-only creation, API-agent integration, assessment import/dispatch/report integration, and the mocked dynamic workflow.
- `TestEnginePostgresClaimsEventsAndRestart` passed against PostgreSQL 16. It applied the migration, raced eight claims, checked outbox deduplication and shared-build membership, reopened the pool after a persisted lease expiry, rejected the old completion token, and checked cancellation.
- `TestEngineHTTPPostgres` passed through real HTTP handlers and PostgreSQL scheduling. It used a real uploaded fixture APK and the real bounded static analyzer, rather than fabricated scan findings.
- TypeScript and Biome checks passed for the changed UI. Both normal and static-export Next.js webpack production builds passed.
- All Go packages compiled. A backend binary started with separate temporary data and database storage; `GET /api/health` returned `{"ok":true,"service":"artex","version":"dev"}`.

The temporary PostgreSQL container was separate from the existing `android-lab-pg` and `artex-pg` instances. Their databases were not migrated or modified during verification.

## Demonstrated assessment

`TestEngineHTTPPostgres` exercises:

1. Upload a controlled APK fixture and preserve its SHA-256.
2. Create an assessment and persistent goals through the existing API.
3. Save an encrypted APK test account; verify its username/password are absent from returned assessment, graph, trace and report payloads.
4. Start the deterministic engine and let the database-backed worker loop settle.
5. Execute real offline APK analysis, inventory/checklist evaluation, provenance updates and reporting.
6. Retrieve searchable worker traces and the graph through authenticated endpoints.
7. Export the existing Markdown draft with build identity, goals and limitations.
8. Create an independent retest using a second uploaded build; confirm original evidence remains, credentials are not copied, and absent new evidence does not prove remediation.
9. Cancel the original engine through its API.

The demonstrated supported-work run recorded 14 intent records (including superseded planning versions), 18 evidence items and 8 adapter traces, while retaining all 91 checklist procedures. It reached a current draft and `waiting_for_evidence`, not a false declaration that runtime testing or all security procedures were complete.

The offline handler-only demonstration also passed. It is available without PostgreSQL:

```bash
go test ./internal/server -run '^TestEngineOfflineAssessmentFlow$' -count=1 -v
```

The HTTP/PostgreSQL demonstration is reproducible with:

```bash
ANDROIDLAB_TEST_PG_DSN='postgres://test-user:test-password@127.0.0.1:5432/test-db?sslmode=disable' \
  go test ./internal/server -run '^TestEngineHTTPPostgres$' -count=1 -v
```

## Full-suite failures and unavailable checks

The full `go test -p 1 ./...` run was executed and did **not** pass. The controlled Android tests passed, but the broader inherited application has failing legacy tests. Examples include:

- `internal/agent/TestGraphOverviewExpandsAssociatedCompanyScope`: expected task/company scope missing.
- `internal/agent/TestReportFindingAtomicContract`: finding registration rejected because traffic evidence storage was unavailable in that fixture.
- `internal/db/TestCreateTaskWithCompanyScopes`: task-company provenance text assertion mismatch.
- `internal/notify/TestChannelValidateReportsMissingFields`: expected strings differ in capitalization/language from current messages.
- Legacy server task/chat/conversation/control tests expect routes that the controlled Android configuration disables (HTTP 409).
- Finding-workflow and notification fixtures also have failing assertions; they were not silently skipped or described as passing.

These tests exercise inherited functionality outside the controlled Android engine. No unrelated legacy feature was enabled in the shipped configuration to make those expectations pass. A diagnostic rerun with legacy execution enabled also encountered legacy scope/localization failures; it is not a release configuration.

Initially the restricted execution environment prevented sockets and provided no test database, causing failures/skips. After access was enabled, the relevant socket and PostgreSQL tests were rerun successfully. The earlier environment failures are not the final integration result.

`adb devices -l` returned no attached devices. Consequently a real ADB/Genymotion install, compatible live Frida session, pinned-app traffic capture and a real device retest were **not** run. Existing mocked runtime tests passed. Browser interaction was not automated; the UI was type-checked, linted and production-built.

## Remaining limits

- Manual login, application use, authorization-policy definition, multi-account comparisons, business-logic testing and reviewed finding dispositions remain required.
- Storage/platform workers evaluate the existing supported observations. They do not add arbitrary local-file extraction, component exploitation, complete signing verification or dependency/CVE confirmation.
- Graphs persist as assessment-owned adjacency records within the existing JSONB aggregate. Only non-sensitive build hashes are shared relationally. The UI renders the first 60 nodes and allows reference inspection; this is not a full large-graph layout engine.
- Traces are at adapter/job granularity. Existing runtime artifacts carry the detailed observations.
- There is no separate planner retry-budget setting: planning is deterministic and local; database recovery uses polling. Worker budgets, work volume, concurrency, local tool limits and observation duration are configurable. The local analyzer checks its context only after returning, so its configured limit is not a hard execution timeout.
- This retains the existing single-operator authentication model and does not introduce tenant-level RBAC.
- The existing live application service was not replaced or restarted. Build/start instructions are in `AUTONOMOUS_ENGINE.md`.

The implementation is functional for its supported workers, but the project's entire definition of done—including a green full repository suite and a live-device demonstration—has not been established.

## Diagnostic full-suite failure list

The diagnostic run with legacy agents enabled reported these failing tests (this setting was used only for testing):

- `TestGraphOverviewExpandsAssociatedCompanyScope`
- `TestReportFindingAtomicContract`
- `TestCompanyScopeAttribution`
- `TestCreateTaskWithCompanyScopes`
- `TestChannelValidateReportsMissingFields`
- `TestFindingWorkflowAutoHintToPlannerAndSetting`
- `TestFindingWorkflowMigrationPreservesUserConfiguration`
- `TestFindingWorkflowReporterBindsBeforeWritingReport`
- `TestInheritedActivityDetailAndRelationDeletion`
- `TestInterceptDetailHTTP`
- `TestJudgeRetrySettingsAndFallbackHTTP`
- `TestNotifyEndToEndRealtimeDelivery`
- `TestNotifyChannelAPICreateValidation`
- `TestTaskMetadataPatchReturnsRenameAndPin`

The final bundled executable also served `/android/assessments/` over HTTP successfully. Verification services were stopped afterward.

## Completion audit

The item-by-item [completion checklist](COMPLETION_CHECKLIST.md) records additional implementation gaps, current focused-test counts, optional skipped fixtures and an explicit **REJECT for full completion** decision. It supersedes any broader interpretation of the supported-work demonstration above. In particular, graph-driven planning, several specialized handlers, cross-worker trace reuse and hard local-tool deadlines remain incomplete.
