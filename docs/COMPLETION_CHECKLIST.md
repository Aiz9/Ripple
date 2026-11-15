# ARTEX Android Security Engine — Completion Verification

Audit date: 2026-10-21. **Overall decision: REJECT for full completion.**

The bounded APK-upload → static-analysis → evidence/graph → draft-report workflow has been demonstrated. This does not establish completion of the full Android assessment, live-device integration, or every worker requirement. No implementation changes were made during this audit.

## Reading this record

Checked items have code inspection and/or executed test evidence for the specific behavior stated. `CODE` means inspection only; `MOCK` means controlled fixtures, not a live Android device. Unchecked items are missing, partial, failed, or unverified; they are not necessarily proven broken. Where a broad claim exceeds available evidence, it remains unchecked.

Evidence references used below:

- **E1**: [engine state, planning and claims](../internal/assessment/engine.go), [goal evaluation](../internal/assessment/engine_graph.go), [engine tests](../internal/assessment/engine_test.go).
- **E2**: [database queue](../internal/db/android_engine.go), [schema](../internal/db/schema.sql), [claim/restart test](../internal/db/android_engine_test.go). PostgreSQL test previously executed successfully, including race detection.
- **E3**: [APK analyzer](../internal/androidapk), [static worker/provenance test](../internal/server/android_engine_test.go). Real bounded parser on fixture APKs.
- **E4**: [runtime adapters/tests](../internal/androidruntime), [dispatch](../internal/server/assessment_dispatch.go). Device operations verified by code and mocks unless explicitly stated.
- **E5**: [API checks/tests](../internal/apicheck), [imports](../internal/assessment/import.go), [API agent](../internal/server/assessment_api_agent.go).
- **E6**: [graph construction](../internal/assessment/engine_graph.go), [engine routes/handlers](../internal/server/android_engine.go), [HTTP/PostgreSQL demonstration](../internal/server/android_engine_postgres_test.go).
- **E7**: [credential handling](../internal/server/assessment_secrets.go), [APK accounts](../internal/server/apk_accounts.go), [assessment HTTP tests](../internal/server/assessment_test.go).
- **E8**: [checklist evidence/status](../internal/assessment/mobile.go), [catalog](../internal/mobiletest/catalog.json), [reports](../internal/assessment/report.go), [retest comparison](../internal/assessment/retest.go), [retest API](../internal/server/android_retest.go).
- **E9**: [engine UI](../web/src/components/assessment-engine.tsx), [assessment page](../web/src/app/(main)/android/assessments/page.tsx), [account form](../web/src/components/apk-accounts.tsx). TypeScript, lint and production builds previously passed; HTML serving checked. No browser interaction test.
- **E10**: [execution results and reproduction instructions](ENGINE_VERIFICATION.md). Fresh audit logs: `/tmp/ripple-checklist-core.jsonl`, `/tmp/ripple-checklist-focused.jsonl`. Earlier integration logs: `/tmp/ripple-engine-final-integration.log`, `/tmp/ripple-engine-http-final.log`, `/tmp/ripple-engine-db-recovery.log`. Logs are temporary local artifacts, not versioned fixtures.

## 1. Core Architecture

- [ ] Existing APK assessment functionality is preserved. — PARTIAL: selected regressions pass; full repository suite fails, live workflow unverified (E10).
- [x] ARTEX-inspired Planner–Worker architecture is implemented. — E1/E6: deterministic intent scheduler and shared handlers, with limitations below.
- [x] Assessment goals are created and persisted. — E1/E2/E6.
- [ ] Goals can be decomposed into smaller goals. — PARTIAL: a preset parent/child hierarchy exists; general goal decomposition is not implemented (E1).
- [x] Investigation intents are generated dynamically. — E1: build, evidence version, endpoints and finding state affect scheduling.
- [x] Workers execute real security-testing operations. — E3/E4/E5: static parser and existing runtime/API adapters; not every named worker adds a test.
- [x] Workers return structured results and evidence. — E1/E6: result state, evidence references, traces.
- [ ] Independent intents can execute concurrently. — CODE supports concurrent goroutines; test proves safe claiming, not overlapping execution of independent operations (E2/E6).
- [x] Dependent intents wait for their prerequisites. — E1 dependency tests.
- [x] Assessment state survives application restarts. — E2 persistence/pool-reopen test; no OS kill/restart demonstration.

## 2. APK Management and Static Analysis

- [x] APK upload works correctly. — E6 HTTP fixture upload.
- [x] SHA-256 is calculated and stored. — E3/E6 hash preservation.
- [x] Package name and version are extracted. — E3 manifest fixtures.
- [x] Minimum and target SDK levels are identified. — E3.
- [x] Permissions and application components are extracted. — E3.
- [x] Exported components are analyzed. — E3 bounded manifest observations, not exploit confirmation.
- [ ] Network security configuration is inspected. — PARTIAL: manifest reference/flags; referenced configuration XML is not comprehensively inspected (E3).
- [ ] Signing and certificate metadata are collected. — MISSING: required signing/certificate parser not established (E3).
- [x] Supported embedded-secret indicators are detected. — E3 supported heuristics only.
- [x] Static observations are stored in the asset and exploration graphs. — E3/E6 evidence and provenance nodes.
- [x] Static indicators are not automatically classified as confirmed vulnerabilities. — E1/E8 candidate/status tests.

## 3. Android Runtime Integration

- [x] ADB device discovery works. — Executed `adb devices -l`; empty device list. Connection to a device was not tested.
- [ ] Genymotion device integration works. — UNVERIFIED: no device attached.
- [x] Device readiness is checked before execution. — CODE/MOCK E4.
- [ ] APK installation works. — CODE/MOCK only; live installation unverified (E4).
- [x] Installed application identity is verified. — CODE/MOCK E4; live behavior unverified.
- [x] APK hash verification works as intended. — CODE/MOCK E3/E4; live installed-build comparison unverified.
- [ ] Application launch is verified. — CODE/MOCK only; no live launch demonstrated (E4).
- [x] Runtime observation duration is configurable between 30 and 300 seconds. — E1 limit tests/E9 input.
- [x] Runtime logs are collected and associated with the correct assessment. — CODE/MOCK E4; no live logs collected in this verification.
- [ ] Compatible Frida instrumentation works when configured. — UNVERIFIED live; adapter/mock coverage only (E4).
- [x] Runtime observations are linked to the APK build and device. — CODE/MOCK E4/E6 runtime-session provenance.
- [x] Device disconnection and instrumentation failures are handled correctly. — Supported failure paths CODE/MOCK E4; not exhaustive live failure testing.
- [x] Manual application interaction is supported during observation. — CODE E4 configurable observation window; saved APK accounts do not log in automatically.

## 4. Autonomous Planner

- [ ] Planner reads the current assessment goals. — PARTIAL: goals are initialized/evaluated; scheduling is fixed rule logic over assessment fields, not driven by arbitrary goal criteria (E1).
- [ ] Planner reads the asset graph. — MISSING: graph constructed after planning; planner uses document inventory (E1/E6).
- [ ] Planner reads the exploration graph. — MISSING: no graph traversal for planning (E1/E6).
- [x] Planner considers existing evidence and checklist coverage. — E1/E8 evidence versions, prerequisites and coverage evaluation.
- [x] Planner identifies missing prerequisites. — E1 blocked reasons.
- [x] Planner creates intents based on actual assessment state. — E1 tests.
- [x] Planner assigns priorities to eligible intents. — E1 explicit priorities.
- [x] Planner avoids unnecessary duplicate intents. — E1 idempotency tests.
- [x] Planner does not schedule dependent tasks prematurely. — E1: may create pending records early, but execution waits for prerequisites.
- [x] Planner responds to relevant new evidence. — E1/E2 document-change wake and version reconciliation.
- [x] Planner can resume after a restart. — E2 durable state/reopen test.
- [ ] Planner respects retry budgets and execution limits. — PARTIAL: worker budgets and volume limits exist; no separate planner retry budget (E1/E2).
- [x] Planner handles assessments with no remaining eligible work. — E6 demonstrated `waiting_for_evidence`.
- [x] Planner operates without an LLM for supported deterministic tasks. — E1/E6.

## 5. Worker Execution

- [x] Static analysis worker executes real tools. — E3 real local analyzer.
- [x] Android runtime worker executes real device operations. — CODE E4/E6 bridges the existing ADB runner; only MOCK execution verified here.
- [ ] API discovery worker identifies and deduplicates endpoints. — PARTIAL: handler gathers existing references; actual extraction/deduplication occurs in static/runtime/import adapters (E5/E6).
- [x] API security worker performs eligible checks. — E5 controlled HTTP fixtures and adapter bridge.
- [ ] Storage security worker performs supported checks. — PARTIAL: handler gathers checklist evidence; no distinct storage inspection in that handler (E6).
- [ ] Android platform worker performs supported component and configuration checks. — PARTIAL: handler gathers existing evidence; static/runtime adapters supply observations (E6).
- [x] Checklist worker maps actual evidence to procedures. — E8 shared reconciliation; handler gathers resulting references.
- [ ] Finding validation worker evaluates supporting evidence. — PARTIAL: checks existing disposition and evidence IDs; substantive review remains manual validation API (E6/E8).
- [x] Reporting worker generates the assessment report. — E6 actual draft generated.
- [x] Every worker validates its intent and prerequisites. — E1/E6 shared claim/capability/dependency gates.
- [x] Every worker records execution results. — E1/E6 shared finish/recovery path.
- [x] Every worker handles errors without silently losing work. — E1/E2 failures/recovery persisted; diagnostic detail limited.
- [x] Workers cannot execute unauthorized targets or operations. — E1/E4/E5 scope/device/policy gates, within existing single-operator model; not a formal proof.

## 6. Asset Graph

- [x] APKs and builds have distinct identities. — E2/E6 SHA-256 identities.
- [x] Application components are represented. — E3/E6 inventory nodes.
- [x] Hosts and API endpoints are represented where applicable. — E6 service-origin and endpoint nodes; no separate host entity.
- [x] Runtime sessions are linked to relevant assets. — E6 session/build/device edges.
- [x] Assets have meaningful relationships. — E6 explicit typed edges.
- [x] Duplicate assets are handled appropriately. — E2/E6 stable identity keys.
- [x] Different APK builds are not incorrectly merged. — E2/E8 distinct hashes and retest tests.
- [x] Evidence is linked to the relevant assets. — E6 provenance edges.
- [x] Assessment-specific information is isolated appropriately. — E2/E6 assessment-owned graphs; only hashes shared.
- [x] Sensitive information is excluded from graph labels and visualizations. — E7 credential fixture/redaction tests; no claim of universal secret detection.

## 7. Exploration Graph

- [x] Goals are represented. — E6.
- [x] Intents are represented. — E6.
- [x] Facts are represented. — E6 operation-outcome facts, limited semantics.
- [x] Findings are represented. — E6.
- [x] Hints are represented. — E6 blocked-intent hints only.
- [x] Evidence references are represented. — E6.
- [x] Goal-to-intent relationships are stored. — E6 `SPAWNS`.
- [x] Intent-to-fact relationships are stored. — E6 `YIELDS`.
- [ ] Fact-to-finding relationships are stored. — MISSING: evidence links to facts/findings independently; no direct fact-to-finding edge (E6).
- [x] Investigation dependencies are represented. — E6 `DEPENDS_ON`.
- [x] Contradictory evidence is preserved. — E1/E6 contradiction tests.
- [x] Investigation provenance can be traced. — E1/E6 intent, execution and evidence references.
- [x] Graph changes are persisted correctly. — E2/E6 JSONB aggregate commits.

## 8. Worker Communication and Execution Traces

- [x] Worker execution traces are persisted. — E2/E6.
- [x] Trace search works. — E1/E6 query tests.
- [x] Trace listing works. — E6 HTTP demonstration.
- [x] Individual execution steps can be retrieved. — E1/E6 step-ID filter; adapter-granularity steps.
- [ ] Workers can retrieve relevant observations from other workers. — PARTIAL: trace retrieval API exists, but handlers do not invoke it; they read shared evidence (E6).
- [x] Trace retrieval respects assessment authorization. — E6/E7 authenticated, assessment-scoped routes; single operator.
- [x] Sensitive values are redacted. — E7 known credential/token tests.
- [x] Trace records include timestamps and execution status. — E1/E6.
- [x] Trace records reference the originating intent. — E1/E6.
- [ ] Failed operations include useful diagnostic information. — PARTIAL: some errors collapse to generic blocked/failed reasons (E6).
- [x] Workers reuse relevant prior observations when appropriate. — E6 shared document evidence; not cross-worker trace reasoning.

## 9. API Discovery and Security Testing

- [x] API references can be extracted from supported APK artifacts. — E3 DEX/resource URL fixtures.
- [ ] Runtime HTTP traffic is captured where supported. — PARTIAL: supported metadata instrumentation, no live capture demonstrated (E4).
- [x] OpenAPI import works. — E5 fixture tests.
- [x] HAR import works. — E5 fixture tests.
- [x] Endpoints and HTTP methods are normalized. — E5.
- [x] Duplicate endpoint records are handled correctly. — E5.
- [ ] Captured requests are linked to their endpoints. — PARTIAL: observation/endpoint links exist; full request/response evidence capture not established (E4/E6).
- [ ] Authentication context is tracked where available. — PARTIAL: configured identity metadata exists; it does not establish authenticated runtime sessions (E6/E7).
- [x] Transport security checks work. — E5 controlled fixtures.
- [x] CORS checks work where applicable. — E5 controlled fixtures.
- [x] Cookie security checks work where applicable. — E5 controlled fixtures.
- [x] Error-disclosure checks work. — E5 controlled fixtures.
- [x] Supported input-handling checks work. — E5 bounded reflection/quote probes; not general fuzzing.
- [ ] Authentication tests use appropriate test identities. — PARTIAL: origin-bound basic/bearer support; no complete authentication test workflow (E5/E7).
- [ ] Authorization checks use controlled comparison requests. — MISSING automated multi-identity/access-policy comparisons (E5).
- [x] Ineligible tests retain explanations. — E1/E5 skip/block reasons.
- [x] Network operations enforce assessment scope. — E5 scope checked on request reservation; redirects disabled.
- [x] Destructive tests are disabled by default or require appropriate approval. — E5 safe methods/route exclusions; unsupported intrusive work is not scheduled.

## 10. Checklist and Finding Validation

- [x] All 91 security procedures remain available. — E8 catalog and tests.
- [x] All 13 checklist sections remain available. — E8.
- [x] Procedures have explicit prerequisites. — E8 catalog/reconciliation.
- [x] Procedures can be associated with evidence. — E8.
- [x] Checklist statuses reflect actual results. — E8 applicability/review gates.
- [x] Automated job completion does not automatically mark a procedure as passed. — E1/E8.
- [x] Missing evidence is identified. — E8 blocked/incomplete reasons.
- [x] Blocked procedures include explanations. — E8.
- [x] Manual procedures remain available for human completion. — E8/E9.
- [x] Candidate findings are distinguished from validated findings. — E8.
- [x] Findings include supporting evidence. — E8 evidence references; missing verification remains explicit.
- [x] Severity and confidence are tracked separately. — E8 model/report.
- [x] Contradictory evidence can be recorded. — E1/E8.
- [x] False positives can be marked as disproved. — E8 false-positive disposition.
- [x] Remediation status is tracked. — E8 validation/retest lifecycle.
- [x] Finding status transitions are auditable. — E8 existing audit plus retained evidence; review is manual.

## 11. Event-Driven Execution and Reliability

- [x] Relevant graph changes trigger replanning. — E2 relevant assessment evidence/document mutations wake planning; graph is a derived projection.
- [ ] Irrelevant events do not cause unnecessary planning rounds. — PARTIAL: exclusions and coalescing exist, but engine state writes can cause additional wakes (E2).
- [x] Duplicate events do not create duplicate work. — E1/E2 event/intent deduplication.
- [x] Concurrent intent claiming is safe. — E2 eight-claim race test.
- [x] Worker crashes are recoverable. — E1/E2 simulated lease expiry; uncertain external work blocks rather than blindly replaying.
- [x] Stale work can be reclaimed safely. — E1/E2 leases and fencing; supported local work retried.
- [x] Retry limits are enforced. — E1 worker retry tests.
- [x] Permanent failures are recorded. — E1 failure/block reasons.
- [x] Assessment cancellation works. — E1/E2/E6.
- [ ] In-flight operations handle cancellation appropriately. — PARTIAL: token fencing and runtime pause checks exist; synchronous local analyzer cannot be interrupted (E6).
- [x] Pending intents survive restarts. — E2 persisted/reopened state.
- [x] Database updates preserve state consistency. — E2/E6 locked JSONB commit and concurrent-merge test.
- [x] Concurrency limits are enforced. — E1 claim limits and E6 bounded pool; execution-overlap test still missing.
- [ ] Per-tool timeouts are enforced. — PARTIAL: local context deadline checked after synchronous analyzer returns; not a hard execution deadline (E6).
- [x] Per-assessment work limits are enforced. — E1 volume-limit tests.

## 12. Reporting and Retesting

- [x] Markdown report generation works. — E6/E8 actual draft export.
- [x] Report includes assessment scope. — E8.
- [x] Report includes APK identity and SHA-256. — E6/E8.
- [x] Report includes static observations. — E8.
- [x] Report includes runtime coverage. — E8 includes absence/limitations.
- [x] Report includes API inventory and coverage. — E8.
- [x] Report includes checklist status. — E8.
- [x] Report includes validated findings. — E8 rendering/tests.
- [x] Report distinguishes candidate findings from validated findings. — E8.
- [x] Report includes evidence references. — E8.
- [x] Report includes blocked and incomplete procedures. — E8.
- [x] Report includes assessment limitations. — E8.
- [x] Report includes remediation guidance. — E8 finding remediation fields.
- [x] Fixed APK builds can be assessed independently. — E6/E8 second-build fixture.
- [x] Retests preserve previous evidence. — E6/E8 original document unchanged.
- [x] Retests compare findings across builds. — E8 unit/HTTP tests; absent evidence remains unverified.
- [x] Remediated, recurring, and new findings are distinguished. — E8 comparison tests.
- [x] Reports do not expose credentials or session tokens. — E7 known-secret/token redaction tests, not universal detection of unknown secrets.

## 13. Frontend and User Experience

UI checks below are CODE/build/HTTP-serving evidence, not browser interaction tests.

- [x] Assessment overview displays the current state. — E9.
- [ ] Goal explorer displays goals and dependencies. — PARTIAL: goals/status/criteria shown; explicit goal hierarchy/dependencies not rendered (E9).
- [x] Intent queue displays pending, running, completed, blocked, and failed work. — E9 status/filter rendering.
- [x] Asset graph is viewable. — E9 first 60 rendered nodes plus reference inspection.
- [x] Exploration graph is viewable. — E9 same bounded graph view.
- [x] Worker activity and traces are viewable. — E9.
- [x] Checklist displays procedure status and evidence. — E9 existing checklist.
- [x] Findings display validation status and severity. — E9 existing findings.
- [x] Blocked tasks display their reasons. — E9.
- [x] Assessment cancellation is available to authorized users. — E6 backend test/E9 control.
- [x] Report export works. — E6 HTTP export/E9 control.
- [x] UI updates reflect execution progress. — CODE E9 three-second polling; browser behavior unverified.
- [ ] Existing UI functionality remains operational. — UNVERIFIED beyond builds and serving; no browser regression suite (E10).

## 14. Security Controls

- [x] Every assessment has an explicit scope. — E1/E5 assessment asset/policy model; absent targets cannot authorize network work.
- [x] Scope is validated before network operations. — E5.
- [x] Discovered external assets do not automatically expand scope. — E1/E5 regression tests.
- [x] Active testing requires appropriate authorization. — E1/E5 explicit policy gate.
- [x] Intrusive operations require additional controls where appropriate. — E5 unsupported destructive operations blocked; no generic intrusive execution facility.
- [x] Credentials are encrypted at rest using the configured secure mechanism. — E7 AES-GCM with assessment-bound associated data.
- [x] Passwords, tokens, and cookies are redacted from traces. — E7 known-value/pattern tests.
- [x] Secrets are not included in planner prompts unnecessarily. — E1 deterministic engine has no LLM prompts.
- [x] Assessment access controls are enforced by the backend. — E6/E7 JWT single-operator authentication.
- [ ] Cross-assessment data access is restricted. — PARTIAL: data is assessment-scoped and trace isolation tested; no per-assessment user/tenant authorization beyond existing single operator (E6/E7).
- [x] Device operations are limited to authorized devices. — CODE/MOCK E4 selected-device checks.
- [x] Missing authorization causes work to be blocked. — E1/E5.
- [x] Imported files and external tool results are handled safely. — E3/E5 bounded parsers/validated imports for supported formats; not a comprehensive hostile-input audit.

## 15. Testing and Deployment

- [x] Database migrations execute successfully. — E2 prior isolated PostgreSQL integration.
- [ ] Existing regression tests pass. — FAIL: full repository suite not green (E10).
- [x] Planner unit tests pass. — E1 fresh run.
- [x] Worker execution tests pass. — E3/E6 supported worker fixtures; missing capabilities remain unchecked above.
- [x] Scope enforcement tests pass. — E1/E5 fresh run.
- [x] Intent deduplication tests pass. — E1/E2.
- [ ] Concurrent execution tests pass. — PARTIAL: concurrent claim test passes; independent execution overlap not tested (E2).
- [x] Retry and recovery tests pass. — E1/E2 simulated expiry/reopen.
- [x] Graph persistence tests pass. — E2/E6.
- [x] Evidence provenance tests pass. — E1/E3/E6.
- [x] Finding validation tests pass. — E8 manual validation contract; not autonomous validation worker reasoning.
- [x] Report generation tests pass. — E6/E8.
- [x] Retest comparison tests pass. — E8.
- [x] Credential redaction tests pass. — E7.
- [x] Assessment isolation tests pass. — E1/E7 reference/credential isolation; not multi-tenant RBAC.
- [x] Frontend build succeeds. — E9/E10 production and static builds.
- [x] Backend starts successfully. — E10 isolated executable health check.
- [x] Database connectivity works. — E2/E10 isolated PostgreSQL.
- [ ] Existing APK assessment workflow still works. — PARTIAL: bounded offline/HTTP flow demonstrated; live Android and complete regressions not established (E10).
- [ ] At least one complete end-to-end assessment has been demonstrated. — PARTIAL: supported-work draft reached `waiting_for_evidence`; not complete runtime/API/security assessment (E6/E10).
- [x] All failed or skipped tests are documented. — E10 failure list plus audit skip inventory below; earlier environment errors distinguished from later successful reruns.

## Final acceptance checklist

- [x] **Architecture:** Planner–Worker execution is implemented and functional. — E1/E6 bounded deterministic implementation.
- [x] **Autonomy:** New investigation intents are generated from actual evidence and assessment state. — E1.
- [x] **Execution:** Workers invoke real tools and persist their results. — E3/E6 supported operations.
- [ ] **Knowledge:** Asset and exploration graphs preserve relationships and provenance. — PARTIAL: useful provenance exists, but required fact-to-finding relationship and richer graph reasoning are missing.
- [x] **Coordination:** Relevant discoveries trigger safe replanning. — E1/E2.
- [ ] **Reliability:** Pending work survives restarts, and failures are handled correctly. — PARTIAL: persistence/recovery proven; local cancellation/deadline enforcement incomplete.
- [x] **Coverage:** Automated and manual checklist procedures are accurately distinguished. — E8; no claim of 91 automated procedures.
- [x] **Validation:** Candidate vulnerabilities are not automatically treated as confirmed findings. — E1/E8; autonomous validation remains limited.
- [ ] **Security:** Scope, authorization, credential handling, and assessment isolation are enforced. — PARTIAL: execution gates/credential tests pass; per-assessment user authorization not implemented beyond single operator.
- [x] **Reporting:** Reports accurately reflect evidence, findings, and limitations. — E6/E8 bounded fixture demonstration.
- [ ] **Regression:** Existing functionality remains operational. — Full suite failures and unverified live/UI paths.
- [ ] **Verification:** The available automated tests pass, and an end-to-end demonstration succeeds. — Full suite fails; only bounded draft demonstration succeeds.

## Completion record

```text
Project: ARTEX-Style Android Security Assessment Engine

Architecture implementation: FAIL (partial implementation against full specification)
Planner and intent scheduling: FAIL (state-driven rules, missing graph/goal-driven planning)
Worker execution: FAIL (real supported adapters; several handlers only gather references)
Asset and exploration graphs: FAIL (missing required fact-to-finding edges)
Event-driven replanning: PASS (bounded deterministic event/intent deduplication)
Runtime and API testing: FAIL (live runtime unverified; auth comparisons missing)
Checklist and finding validation: FAIL (checklist works; autonomous validator incomplete)
Security controls: FAIL (single-operator scope; broader assessment authorization incomplete)
Reporting and retesting: PASS (controlled fixtures; live device retest unverified)
Frontend and deployment: FAIL (build/start pass; UI regression acceptance unverified)

Automated tests, fresh focused audit:
  Passed: 93 test/subtest pass events (81 core + 12 server/database)
  Failed: 0 in these focused runs
  Skipped: 8 (2 external-fixture checks + 6 PostgreSQL-dependent checks)

Earlier verification:
  PostgreSQL integration and selected race-detector runs: PASS
  Full repository suite: FAIL
  Diagnostic full suite with legacy agents enabled: 14 failing tests
  Frontend builds/typecheck/lint: PASS

End-to-end assessment: FAIL against full definition of done
  Bounded fixture APK-to-draft HTTP/PostgreSQL demonstration: PASS

Known limitations:
  - Manual login, application use and reviewed validation remain necessary.
  - No live Android/Genymotion/Frida or browser interaction verification.
  - Graph planning, richer discovery/storage/platform/validation handlers incomplete.
  - No automated policy-aware multi-account authorization comparisons.
  - Trace API exists; workers do not query prior worker traces.
  - Local analyzer has no interruptible hard timeout.

Outstanding issues:
  - Resolve incomplete critical acceptance items above.
  - Fix full-suite failures and establish regression baseline.
  - Demonstrate live-device workflow and independent concurrent execution.
  - Add per-assessment authorization if multiple operators are supported.

Overall decision: REJECT
```

PASS in this record means the stated bounded behavior was verified, not every possible input/environment. FAIL includes unmet or unverified requirements; it does not mean all existing functionality is broken.

## Test accounting and skips

Fresh audit commands (Go 1.26.8):

```bash
GOCACHE=/tmp/ripple-go-cache go test -json ./internal/assessment ./internal/androidapk ./internal/androidruntime ./internal/apicheck
GOCACHE=/tmp/ripple-go-cache go test -json ./internal/server ./internal/db \
  -run '^(TestEngine|TestAPKAccount|TestAssessmentAPK|TestAssessmentCredential|TestAssessmentLegacy|TestAssessmentHTTPPostgres|TestAPIAgentHTTPPostgres|TestDynamicWorkflowPostgres)' -count=1
```

Counts are Go JSON test/subtest events, not distinct top-level tests. The core command can use the Go cache. The focused server/database command disables it. These results must not be combined with the earlier full-suite failures as though they were one test run.

Fresh skips:

1. `TestDifferentialExport`: `APK_DIFFERENTIAL_INPUT` and `APK_DIFFERENTIAL_OUTPUT` absent; external APK corpus runner not configured.
2. `TestIndependentZAPFixture`: `API_ZAP_VALIDATION_OUTPUT` absent; optional independent local ZAP validation not configured.
3. `TestEnginePostgresClaimsEventsAndRestart`.
4. `TestEngineHTTPPostgres`.
5. `TestAPIAgentHTTPPostgres`.
6. `TestAssessmentAPKOnlyHTTPPostgres`.
7. `TestAssessmentHTTPPostgres`.
8. `TestDynamicWorkflowPostgres`.

Items 3–8 skipped because `ANDROIDLAB_TEST_PG_DSN` was absent in this fresh audit. All six previously passed against isolated PostgreSQL during implementation verification (E10); the temporary container was then stopped. Their earlier successful evidence is retained, not described as a fresh execution. No live device is attached. Full-suite failures are listed in [ENGINE_VERIFICATION.md](ENGINE_VERIFICATION.md); a clean original-baseline comparison was not run, so those failures cannot be asserted to predate these changes.
