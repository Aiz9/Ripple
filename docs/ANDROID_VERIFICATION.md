# Ripple verification

Verified on 2026-10-20 with Go 1.26.8, Node 26.7.0 and Next.js 16.2.9. Parent ARTEX source/data were not modified by this work.

## Passed for the controlled assessment implementation

- Production static frontend build and Next.js TypeScript checks: all 34 routes generated, including `/android/assessments`.
- Standalone executable built with `CGO_ENABLED=0 go build -tags embedui -trimpath -o androidlab ./cmd/artex`.
- Race-enabled targeted suite against an isolated PostgreSQL 16 container:

```bash
ANDROIDLAB_TEST_PG_DSN='postgres://.../isolated-test-db' \
  go test -race ./internal/assessment ./internal/androidapk ./internal/server \
  -run 'TestAssessment|TestAndroid|TestAPK' -count=1
```

All three packages passed, including `TestAssessmentHTTPPostgres`. Covered:

- exact origin/path boundaries, ports/protocols, traversal and encoded-path rejection;
- explicit URL exclusions and current policy re-evaluation;
- no inference of coverage from discovery, scanner severity or successful HTTP responses;
- historical evidence requiring review, with role/property/parameter/environment/revision/freshness matching;
- historical authenticated coverage retained without exposing/storing the old credential;
- newer applicable retest results superseding older evidence;
- OpenAPI security/server overrides, HAR data minimization, source provenance and atomic import rollback;
- source originals encrypted at rest and redacted source retrieval;
- authenticated encryption, cross-assessment binding and tamper rejection for credentials;
- role-bound HTTP credentials, no redirects, no response body retention, request-rate/budget checks and automatic error stops;
- a separate database connection observing the committed execution reservation before the target receives the HTTP request;
- unresolved/expired reservations recovering as inconclusive with policy paused;
- candidate/validated separation, unrelated-role evidence rejected and old no-issue evidence rejected as proof of a later fix;
- default blocking of legacy shell-capable execution routes;
- APK manifest/ZIP bounds, fake directory metadata rejection and offline URL discovery without invented methods or approved hosts.

## Fuzzing

The scope/URL fuzz target completed **611,418 executions** in eight seconds with two workers and no crash. It exercised normalization, scope checks and URL metadata handling, including malformed/encoded URL input.

The earlier manifest fuzz run completed **1,009,792 executions** in about nine seconds without crashes. Binary/text manifest, UTF-8/UTF-16, malformed chunk and unresolved-resource tests continue to pass in the targeted suite.

## Browser and build validation

The assessment browser smoke test passed after the final UI changes:

- all seven tabs: scope, API inventory, planner, evidence, findings, execution/audit and report;
- import, policy, manual evidence, candidate, evidence-review and validation dialogs;
- manual-test save disabled until explicit attestation;
- affected-role input for validation;
- 390px mobile layout without horizontal page overflow;
- APK-to-assessment handoff with the uploaded artifact preselected;
- no application exceptions.

The page uses clearly labeled simulated data. No demo button executes real tests. Screenshots: `screenshots/assessment-planner.png` and `screenshots/assessment-mobile.png`.

Changed frontend files passed Biome; TypeScript passed. Shell syntax checks for build/run/development scripts passed in the initial platform verification.

## Real artifact and final standalone check

The rebuilt offline inspector successfully analyzed the installed `/usr/share/android-framework-res/framework-res.apk`: Android 13.0.0, package `android`, target SDK 33, 7,725 entries and 74 components. The new archive preflight accepted the valid APK.

A final smoke test used the rebuilt embedded executable, a separate temporary PostgreSQL database and temporary application data. It verified JWT enforcement, real APK upload/hash, controlled assessment creation, the offline APK action, report export and rejection of the old task-execution route.

For that framework APK, the controlled action produced **34 candidate findings**, **zero literal API URL candidates** and **zero outbound test-request attempts**. All findings remained unvalidated. Unknown-method and unapproved-host handling was separately exercised with APK fixtures containing two URL literals. No runtime application code was installed or executed.

The temporary backend, browser and PostgreSQL container were stopped after verification. The simulated development preview remains available separately on port 3001.

## Limits and remaining work

For the initial coverage MVP, no provider key was configured for a real model call; planning advice was not tested against a live LLM. That initial pass did not perform production/remote-target testing, active scanner jobs, emulator setup, runtime installation or instrumentation. The subsequent live Genymotion work is recorded below. Scanner JSON import does not imply scanner execution.

## Live Genymotion verification — 2026-10-20

The user's existing Genymotion instance was reachable through ADB at `127.0.0.1:6555`: Android 11, API 30, x86_64. Allsafe was already installed as `infosecadventures.allsafe`. Its installed APK was copied into the new platform, uploaded and analyzed; SHA-256 was `d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9`.

The live assessment `accb46bf-452e-4845-8022-05e0030fa08c` uses the separate Android database at localhost:55434. Database credentials live in ignored, mode-0600 `Android/config.json`; the original ARTEX database and settings were not changed. The frontend was restarted with mock mode disabled and is connected to the actual backend.

Observed runtime jobs:

- Package/device inspection completed, including matching the installed APK hash.
- Launch and PID-filtered log collection completed.
- The first Frida job was inconclusive: the matching server binary existed but was not running. That failed attempt remains recorded.
- The existing Frida 17.22.2 server was started on the emulator loopback address 127.0.0.1:27042. The next instrumentation job attached successfully, emitted its readiness event, initialized the `java.net.URL(String)` and `javax.crypto.Cipher.getInstance(String)` hooks, and detached after ten seconds. Hook initialization alone is not a vulnerability or evidence of complete endpoint discovery.
- An in-flight Frida job was cancelled through the job API; it became cancelled and retained partial evidence.
- A second in-flight Frida job was stopped by pausing assessment policy; it became cancelled. Policy was then explicitly resumed.
- Installation of the same approved APK with `-r --no-streaming` completed, retaining application data, followed by successful launch/log collection and another successful Frida observation.

At that point nine persisted runtime jobs existed: six completed, two cancelled, one inconclusive. Original evidence artifacts are encrypted and authenticated downloads are redacted. No candidate vulnerability was promoted merely because these observations completed.

The rebuilt standalone backend was then restarted. All nine job records remained available, and a new inspection completed successfully. The assessment also ran offline APK triage: 33 literal URL observations and nine candidate findings, with zero validated vulnerabilities. The consolidated Markdown report was saved under `Android/data/allsafe-genymotion-report.md`. The standalone backend serves the production frontend at localhost:8797; the live development frontend remains at localhost:3001.

Automated validation passed: race-enabled runtime/assessment/server tests against a separate test database, including transaction rollback, cross-assessment device exclusion, explicit cancellation, encrypted evidence, redaction and interrupted-job recovery. Adapter tests reject shell-like inputs, verify both uploaded and installed APK hashes, bind every command to the selected device, require verified PID ownership, and prevent attachment to a mismatched installed build. Frontend TypeScript, Biome and the production build passed. A real Chrome browser rendered the live runtime tab, device selection and nine evidence downloads; desktop and 390-pixel mobile layouts had no page overflow.

Screenshots: [desktop runtime](screenshots/runtime-genymotion.png), [mobile runtime](screenshots/runtime-genymotion-mobile.png).

These runs did not execute active ZAP/MobSF scanner submission, Objection scenarios, automatic private-storage extraction, TLS/pinning bypass or business-logic exploitation. No LLM provider was configured or called, and no remote target security tests were run.

## APK-only optional-input verification

The create form now puts the APK first and groups consumer/admin websites, API URLs and credentials in a collapsed optional section. The authenticated assessment API accepts APK-only requests with omitted credentials, environment and revision. It derives `local-device` and the APK hash when those context fields are blank; explicit context is preserved. No web/API target is inferred from the APK.

Race-enabled regression coverage verified an APK-only HTTP assessment request, mobile planning, device policy authorization and persisted runtime submission without websites or test accounts. It also verified that missing device permission still blocks execution, and that web assessments still require their context. TypeScript, Biome and the production build passed.

A real Chrome browser created assessment `6cea5264-a3be-46ea-aa96-f7bb4749c4e4` with only a name and the Allsafe APK selected. Consumer/admin website fields, API URLs, credential fields, environment and revision were all left blank. The resulting assessment contained one Android asset, zero web/API assets and zero test accounts. Device inspection, launch/log collection and Frida observation completed successfully on Genymotion `127.0.0.1:6555`. The mobile layout had no page overflow.

Screenshots: [APK-only create form](screenshots/apk-only-create.png), [APK-only runtime](screenshots/apk-only-runtime.png). Runtime job references are stored in `Android/data/apk-only-verification.json`.

## APK-derived API security testing

The automated API workflow is now connected to discovery: **Run API security agent** verifies the APK, extracts attributable app-class/resource URLs, reconciles captured request methods and executes predefined, bounded checks. Manually entered consumer/admin websites, API URLs and test accounts are optional inputs to this workflow, rather than prerequisites for API testing.

The live Chrome run on assessment `6cea5264-a3be-46ea-aa96-f7bb4749c4e4` started job `a700f57b-b920-41c0-b870-8e936ab10b24` through the new button. The assessment still had one Android asset, zero manually declared web/API assets and zero test accounts. Discovery produced 35 deduplicated endpoint records. Two app-backend routes were eligible and received two actual HTTP probes; 33 reference/service routes were skipped with recorded reasons.

Compiled resource decoding found `allsafe-8cef0.firebaseio.com`, which the previous raw-literal search had missed. The root probe returned HTTP 301 and was not followed. The derived Firebase REST metadata probe returned HTTP 200 to anonymous `GET /.json?shallow=true`, with metadata for two top-level keys. Key names and database values were not retained. This produced one new **candidate** for unauthenticated Firebase metadata access. It was not promoted to a confirmed vulnerability; the existing nine manifest candidates remain separate.

The API report and job references are in `Android/data/api-agent-verification.json`. Source JSON is encrypted in the assessment database, check observations and hashes appear in evidence, and skipped reasons are included in coverage/report records. Screenshots: [API agent](screenshots/api-agent-runtime.png), [discovered inventory](screenshots/api-agent-inventory.png). The 390-pixel browser layout had no overflow.

Race-enabled package/server/database checks passed. Controlled API tests reproduced CORS reflection, session-cookie flag issues, unescaped HTML reflection and query-triggered database diagnostics. Negative controls reject generic error-status changes as injection proof, exclude references and state-changing routes, block private DNS answers, avoid redirects, and preserve actual runtime request methods. Firebase tests enforce an anonymous shallow query and ensure key names are not retained. DEX parser fuzzing completed 14,706 executions without a crash. Biome, TypeScript and the production build passed.

No live LLM request was made. This workflow uses deterministic check selection and permission enforcement; the configured-provider advisory feature remains separate. Runtime HTTP hooks are implemented for supported OkHttp/URLConnection clients, and other clients/obfuscated code may require additional runtime evidence. Multi-account authorization and state-changing business workflows are not claimed covered by these read-request checks.

The full Docker image was not built in this session. APKs with ZIP64/multidisk/unsupported directory layouts are intentionally rejected rather than processed without bounds.

## Inherited regression-suite status

Before this controlled workflow was added, `go test ./...` was attempted without a test database. Several inherited server integration tests failed rather than skipping, and `notify.TestChannelValidateReportsMissingFields` retained case-sensitive English/Chinese assertions that did not match the already translated messages. These are not reported as passing.

The complete inherited suite was not rerun as a substitute for the targeted checks above. Legacy execution tests now also require explicit `ANDROIDLAB_ENABLE_LEGACY_AGENTS=1`, since the production default intentionally disables that execution mode. The new boundary tests explicitly exercise the disabled default. Use only a separate test database for database-backed regression tests.

## Automatic dynamic workflow verification — 2026-10-21

The general **Run Assessment** workflow was started through the live browser UI on the rebuilt backend, using the latest Citytouch upload as a verification case. Application selection remains per assessment; no Citytouch/Allsafe package is hardcoded in the runner.

- Assessment: `e97d2b62-a872-4e89-9aaf-3aea7d55bbb9`.
- Device: `127.0.0.1:6555`; package: `com.app.citytouch`.
- Uploaded/installed SHA-256: `de21e90e9a212545266a817b4d43ed5710a97a2998d706c8b8db1d2ae0a664ce`.
- Dynamic job: `a287cb06-0783-4077-9ec7-a7deb9b78514`, completed installation, installed hash verification, launch and a 60-second Frida window.
- Runtime events: 1 ready event, 7 hook initialization events, 5 storage-mode observations; no supported HTTP request events.
- Dynamic check outcomes: 7 observed, 6 inconclusive, 6 not performed. No security pass was inferred from missing events or unavailable private-data access.
- Automatically queued API child: `b253b22f-04dc-49e0-8802-e25b71634ab3`, completed with 69 discovered records, **0 eligible**, **0 HTTP attempts**, and 69 explicit skips. This run does not establish API vulnerability coverage.
- The browser showed the final dynamic checks, coverage gaps and completed API continuation.

Local verification artifacts are under ignored `data/dynamic-workflow-verification/`: `browser-result.json`, `browser-results-verification.json`, `live-summary.json`, `regression-tests.log`, and browser screenshots. Detailed runtime artifacts remain encrypted assessment sources in PostgreSQL. The 13 candidate records after the API stage include APK triage; this count must not be represented as 13 confirmed dynamic vulnerabilities.

The targeted Go race suite (including a disposable PostgreSQL integration test), TypeScript checking, Biome checking, JavaScript syntax checking and production application build passed. Integration tests cover selected APK/device binding, observation-duration limits, longer dynamic leases, repeat runs, atomic API continuation, duplicate completion, cancellation, failed-install behavior and preserving inconclusive/not-performed outcomes. No generalized automated UI navigation, credential entry, multi-account authorization testing or certificate-validation/pinning test was verified.
