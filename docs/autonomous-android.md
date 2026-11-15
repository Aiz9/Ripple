# Autonomous Android assessment — root causes and design

Status: living design note for the APK → testing → validated findings → final
report pipeline. Benchmark: AllSafe 1.5
(`d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9`).

## Original root causes (baseline review, 2026-10-28)

These citations describe the baseline before implementation. They are retained
as the original review record; line numbers moved as the fixes below landed.

| ID | Verdict | Evidence |
|---|---|---|
| R1 human review gate | **Confirmed** | `internal/assessment/planner.go:12` `Applicable` requires `ReviewedBy != ""`; reuse at `planner.go:67`; `ValidateFinding` needs applicable evidence (`planner.go:246`). `internal/server/android_engine_workers.go:136` calls `ValidateFinding`, then `:143` discards it with `work = cloneAssessment(d)`. `internal/assessment/report.go:26-31` `FinalReport` errors on any unresolved finding. Mobile procedure rows only pass/fail with reviewed evidence (`internal/assessment/mobile.go:47-56`), and `RecordMobileSignal` strips `ReviewedBy` (`mobile.go:117`). |
| R2 no executors | **Confirmed** | `MobileObjectives` (`internal/assessment/model.go:20`) are planned as `Action: "manual"` (`planner.go:136-141`). `storage`/`platform` workers map to `inspectAPKConfiguration` (`internal/server/android_engine.go:397-398`), which only re-reads the manifest (`android_engine_workers.go:26-77`). `internal/androidruntime/checks.go:29-41` records `ls -ld` and `run-as id` and explicitly reads no contents. |
| R3 no UI driver | **Confirmed** | `internal/androidruntime/checks.go:43` "No automatic credential entry or workflow navigation is performed". `internal/server/apk_accounts.go:70` stores accounts; nothing types them. No uiautomator/`input` code exists in the tree. Frida observer is passive (`internal/androidruntime/runtime.go:318`). |
| R4 no proxy routing | **Confirmed** | No `settings put global http_proxy` or system-CA install in Go code. The recording proxy listens on `127.0.0.1:8798` (`cmd/artex/main.go:58`), which the emulator cannot reach without `adb reverse`. Runtime endpoint ingestion only uses Frida `request` events (`internal/server/android_runtime.go:494-529`). The device was found with a stale `http_proxy=127.0.0.1:3333` from an earlier run. |
| R5 shallow static | **Confirmed** | `internal/androidapk/dex_urls.go:73-86` only scans string data of classes under the package prefix, with a work budget and 16 MiB decode cap (`:53,:76`). `internal/androidapk/configuration.go:39` "Network security configuration resource ID could not be resolved". No jadx/apktool invocation anywhere. |
| R6 noise as coverage | **Confirmed** | `internal/androidapk/analyze.go:203` emits "Review exported …" as findings. Reference URLs are planned as `blocked` rows (`planner.go:103-115`) although `DiscoveryExclusion` already knows they are references (`internal/assessment/discovered_scope.go:20-55`). |
| R7 two runtimes | **Confirmed** | `internal/server/android.go:236-283` (`androidAssessment`) builds a generic `createTaskReq` and calls `s.createTask` (web agent chain). The typed engine's only LLM calls have no tools: `internal/server/android_goal_planner.go:47`, `internal/server/assessment_advice.go:49`. |
| R8 known bugs | **Confirmed** | `internal/androidruntime/runtime.go:238` skips `sha256sum` when `alreadyInstalled` (only `observe`/`instrument` re-check at `:250`). Frida attach is post-launch `-p <pid>` (`runtime.go:330`). `internal/server/android_engine.go:307` 5 s claim deadline around `ClaimAssessmentIntent`, which unmarshals/replans/remarshals the whole document under a row lock (`internal/db/android_engine.go:14-64`); stored engine documents reach 3–5 MB with ~1,400 evidence rows and ~2,000 graph nodes. Goal planner: `DisallowUnknownFields` (`android_goal_planner.go:120`), `MaxTokens: 2500`, 45 s (`:46-47`); all 7 logged runs failed with `invalid model plan: EOF` (100 % fallback). |

Additional finding: with `TaskFlow`, every worker waits for a `goal_planning`
intent of the *current* `EngineVersion` (`internal/assessment/engine.go:526-531`), and
the version hashes all evidence (`engine.go:164`). Each evidence commit therefore
re-serializes the queue behind another planner run.

## Design

### Policy and review
- `Policy.ReviewMode` = `manual` (default, unchanged) | `autonomous`.
  `Policy.BudgetMinutes`, `Policy.ScopeHosts` drive termination and network scope.
- `Policy.PlanningMode` = `deterministic` | `model`. Autonomous mode defaults to
  deterministic planning; manual mode preserves its configured model behavior.
  Explicit model planning is optional and cannot grant execution permissions.
- `internal/assessment/autoreview.go`: registry of proof criteria keyed by check ID
  (`masvs.storage.prefs_plaintext`, `masvs.platform.provider_rows`, …). A worker
  emits `Evidence` plus a typed `Proof` (kind, matched canary hash, artifact IDs).
  In autonomous mode the reviewer sets `ReviewedBy = "auto:<check>@<ver>"` only
  when the check's `Verify(Proof)` passes. Human review keeps working unchanged.
- Finding status `unconfirmed` (terminal, non-blocking) when every relevant
  intent is terminal and no proof exists.
- `FinalReport` in autonomous mode never blocks; sections: Validated
  (automated), Unconfirmed, Not applicable, Coverage gaps and blockers.
- Labels: `validated (automated: <check-id>)` versus `validated (reviewed: <who>)`.

### Device layer (`internal/devicelab/`)
- `Device`: serial-bound adb wrapper; every package-touching command takes the
  approved package (hash-verified) — no free-form shell from the LLM.
- Per-serial lease uses in-process coordination and an OS file lock shared by
  CLI and server processes. Existing legacy runtime jobs retain their DB lease
  too. OS locks release on process death; their lock files are never unlinked.
- Planned scoped proxy: `adb reverse tcp:8798 tcp:8798` + `settings put global http_proxy
  127.0.0.1:8798`; MITM CA installed into the system store (tmpfs overlay on
  `/system/etc/security/cacerts`, and the conscrypt APEX path on Android 14+).
  Reverted by `defer` and at the next preflight. **This path is disabled for
  autonomous execution until scope enforcement and ownership-safe CA recovery
  are implemented and validated.** Current autonomous runs install verified,
  uniquely tagged IPv4/IPv6 app-UID REJECT rules before any app tests, stop the
  app at teardown, remove only their own rules and retain failed-cleanup journals.
- UI: `uiautomator dump` → compact node JSON; `input tap/text/swipe/keyevent`;
  screenshots with password-field masking (bounds of `password=true` nodes are
  blacked out before storage).
- Canary: `ARTEX-CANARY-<assessment8>-<n>`; credentials are placeholders
  `{{account:<role>.<field>}}`, resolved only inside `devicelab` input actions.

### Static depth (`internal/staticx/`)
- jadx + aapt2; the server caches under `data/android/static-cache/<sha>/`,
  the standalone CLI under `reports/.cache/static/<sha>/`. Complete facts are
  published atomically and reused only for matching APK, extractor and tool
  versions with an existing application source tree. Partial decompilations are
  available for the current run but are retried on the next analysis.
- Facts: exported components + intent extras keys, UriMatcher authorities/paths,
  deeplink schemes/hosts/query keys, JS interfaces, crypto call sites, prefs
  names, secrets (patterns + entropy), resolved network_security_config.

### Workers (typed, deterministic unless noted)
The architecture below remains the target. The current executor is one durable
`device_assessment` intent after `apk_static`, reusing the CLI's `devicelab.Assess`
implementation. It records per-check results and does not mark missing checks
passed. Autonomous runs supersede the older manifest-only storage/platform and
passive runtime intents; manual mode keeps those workflows.

`static_deep` → `ui_explorer` (LLM tool-driving, BFS fallback) →
`storage_scan`, `log_scan`, `component_tests`, `deeplink_tests`,
`webview_tests`, `crypto_tests`, `protection_tests` (root/PIN/native/FLAG_SECURE
via Frida spawn), `network_tests` (cleartext, pinning, bypass) →
`auto_review` → `report` (auto-finish).

### Engine fixes
- Claim: 30 s deadline, non-overlapping ticks and indexed graph lookups.
  General trace/fact/history compaction remains unfinished.
- Autonomous runs plan once per run, not per evidence version.
- Budget: `BudgetMinutes` deadline → remaining intents `cancelled: budget`,
  report still produced.

## Phase order
0 harness/preflight/scoring → 1 autonomous review → 7 engine bugs that block
e2e (claim, hash verify, single APK path) → 4 traffic → 3 UI explorer →
2 device executors → 5 static depth → 6 report quality.
Each phase: AllSafe e2e + `scripts/score_allsafe.py`, record the score here.
The operator explicitly chose local-only work without Git commits. A phase with
pending live verification does not claim a new score or advance the live gate.

## Progress log

- **Baseline (2026-10-28):** `score_allsafe.py` on the three stored AllSafe reports:
  automated 0/19, validated 0–1/19, detected 4–5/19. All "findings" are
  "Review exported X" informational items plus one Firebase candidate.
- **Phase 1 (autonomous review) landed.** New: `Policy.ReviewMode`/`BudgetMinutes`/`ScopeHosts`;
  `internal/assessment/autoreview.go` (25-check catalog with proof criteria, CVSS v3.1
  scoring, canaries, coverage rows, `RecordCheck`/`AutoReview`/`SettleFindings`);
  `internal/assessment/report_autonomous.go` (non-blocking four-section report);
  engine auto-finish + budget termination + plan-once-per-run; manifest triage
  routed to coverage, not findings, in autonomous mode. `go test ./internal/assessment/` green.
- **Historical device-layer checks** used the live Genymotion
  emulator (127.0.0.1:6555, AllSafe, API 31, x86_64, su root): serial+package
  bound adb wrapper, always-on installed-hash verification (R8), per-serial lease,
  uiautomator→compact-node parser
  with screen signatures, canary-typing input with placeholder resolution at the
  tool boundary, password-masked screenshots, storage snapshot restricted to the
  package's own roots, SQLite dump, UID-filtered logcat. Frida **spawn mode**
  confirmed working end-to-end (hooks load at startup). FLAG_SECURE verified:
  screencap returns 0 bytes on the protected activity, valid PNG elsewhere.

## Local continuation — 2026-10-29

The operator requested that all work requiring Daybreak remain pending. No
Daybreak integration or external model service was contacted during this local
continuation. Its live integration/credential validation remains pending.

### Implemented locally

- Autonomous proof review persists through the normal validation contract.
  Missing proofs, wrong revisions/environments, expired and future observations
  become inconclusive. Manual review continues to require an operator.
- Removed false confirmations: normal provider selection is not SQL injection;
  a URL constructor is not transmitted traffic or a Firebase read; a WebView
  load is not JavaScript execution; static weak crypto needs runtime evidence;
  a service start message needs evidence that the service actually ran.
- The score script requires the matching automated reviewer and typed check ID.
  Provider SQL observations cannot count as the separate local SQL challenge.
- The typed queue now schedules the actual local `device_assessment` worker.
  Its input version includes APK/build, environment, device, scope and account
  references, so new evidence does not restart the crawl. Result merges retain
  canary provenance, per-check coverage and the intent's execution binding.
- The former `/api/android/apps/{id}/assessments` endpoint now creates and starts
  a typed assessment instead of calling `createTask`. It preserves static vs
  dynamic authorization and defaults to manual review with deterministic
  planning. `review_mode: autonomous` is additive. Its response is an assessment
  document; the unused frontend client helper's type was updated accordingly.
- `start_engine: true` on typed creation starts the durable engine with the
  submitted policy. Autonomous clocks start at execution, not draft creation.
  Budget expiry cancels testing but leaves final-report authority available,
  including when goal planning has not completed. Pausing still stops workers.
- Cross-process device locks cover both execution paths. Input and capture
  reject foreign foreground apps. Checkable drawer items are retained, an
  instrumented process is preserved, and hiding an already-hidden keyboard
  cannot accidentally navigate back.
- Frida requires initialized hook groups and matching client/server versions.
  Existing daemons are reused. Newly started daemons have recovery journals;
  cleanup compares PID, kernel start time and executable before signaling.
  Failed cleanup retains ownership metadata. This change has host-process tests;
  its on-device validation is pending.
- Account placeholders resolve at input time. Known credentials and recovered
  literals are redacted before result persistence. Canary excerpts contain only
  synthetic markers and offsets; provider results are hashed. Observer URL events
  contain origins only. Live-test diagnostics no longer print decompiled secrets
  or SQLite contents. The grep scanner reports filenames without exposing its
  secret patterns.
- The device runner independently verifies that its device, package, APK hash,
  subject and network options match the document's active authorization. Static
  decompiler warnings are retained as report limitations even when device work
  cannot start.
- `./run-android.sh assess` builds a private CLI binary and owns a private ADB
  server, without starting the web server or DB. Shutdown gives assessment
  cleanup time before stopping ADB. MD/HTML/PDF exports use private permissions;
  PDF failures return failure while retaining MD/HTML. Reports list missing
  catalog checks and include the recorded proof and revision/environment binding.

### Recorded AllSafe results

The latest completed **device run predates the final local changes above**:

| Run | Automated challenges | Other validated items | Runtime | Deliverables |
|---|---|---|---|---|
| `d72f696d-cdb8-4616-aba8-0a40731c1989` | **4/19** | debuggable, backup flag, hardcoded key | 100 seconds | `reports/<id>/final.md`, `.html`, `.pdf`, `assessment.json`, `score.json` |

The four challenge hits are hardcoded credentials, deep-link exploitation,
receiver injection and provider exposure. The explorer recorded 3 screens,
5 steps and 4 typed fields. The known APK-literal grep passed for its JSON,
Markdown and HTML exports. This scan does not establish that historical DB
documents or every past transcript is free of secrets. Raw analysis caches
contain APK literals by design and are excluded from evidence-export scans.

Earlier 5/19 and 6/19 claims included proofs subsequently rejected. They are not
accepted recall results. **The required 14/19 recall has not been achieved.**

### Verification and pending gates

- `go build ./...`, `go vet ./...`, the complete Go suite and frontend typecheck
  passed during local verification. The full suite also passed using
  `scripts/test-postgres.sh`, which creates and removes only its disposable test
  container and exercises the real queue, HTTP routes and DB migrations.
- An additional isolated HTTP test proves autonomous final-report completion
  with missing-device and expired-budget cases and zero provider invocations.
- Offline analysis of the real approved AllSafe APK completed in 29 seconds:
  12 components, 6 crypto call sites, 5 recovered credential/key literals and
  one warning. The analysis is **partial**, so its facts are not reused as a
  complete cached result. This is static extraction evidence, not live challenge
  proof or a new recall score.
- Python launcher/scorer/secret-scanner tests: 13 passed. Frontend tests: 8 passed.
  Race checks cover assessment, host device leases, device helpers and report CLI.
- The initial live retry had no connected device and `adb connect
  127.0.0.1:6555` returned **Connection refused**. It subsequently reappeared,
  but root is disabled: shell UID 2000, `persist.sys.root_access=0`,
  `ro.debuggable=0`, no `su`, and the root daemon stopped. The existing proxy is
  still `127.0.0.1:3333`; this pass did not change it or enable root. Typed-worker
  live validation, new daemon cleanup, post-run settings inspection,
  repeated-install verification and a score for the current implementation remain
  pending a root-enabled authorized emulator, because the default-deny guard
  cannot safely run without it.
- Daybreak-dependent validation stays pending separately. It is not a reason
  to mark unfinished local executors as complete.
- Remaining implementation: scope-enforcing/redacted proxy capture and safe CA
  ownership; real before/after PIN/root/native/FLAG_SECURE proofs; local SQL
  exploit checks; observed WebView JavaScript callbacks; better UI coverage;
  artifact-backed replay/verification; queue history compaction; and full CLI
  orchestration through the durable queue. Firebase direct probing remains
  prohibited by the operator's app-traffic-only decision.
- Proxy-log scope acceptance is **pending**. Denying all app-UID egress is a
  local safety boundary, not proof that scoped interception has been completed.

### Autonomous planner and adaptive bypass (2026-11-04)

- **`internal/devicelab/planner.go`**: Static protection detector. Scans `Facts.NativeLibs`,
  `Facts.NetworkConfig`, and decompiled source (up to 2000 files) for root detection
  libraries (RootBeer, SafetyNet, PlayIntegrity, Magisk, Flutter jailbreak plugins)
  and SSL pinning patterns (OkHttp CertificatePinner, custom TrustManager, conscrypt,
  network_security_config pin-set). Produces a `ProtectionPlan` with `FlipRoot`,
  `FlipSSL`, and app-specific `FlipMethods`. Four unit tests pass.
- **`internal/devicelab/instrument.js`**: Added SSL pinning bypass hooks (TrustManagerImpl.verifyChain,
  OkHttp CertificatePinner.check) behind `CFG.ssl_bypass`, active only when the
  planner detects pinning. Emits `ssl_bypass_applied` events for audit.
- **`internal/devicelab/assess.go`**: Planner runs before Phase C. Decisions logged to
  `doc.RunInfo["plan_root_bypass"]` and `doc.RunInfo["plan_ssl_bypass"]`. Adaptive
  retry: if the first pass fails without any bypasses enabled, retries with full
  bypass (catches protections that static analysis missed).
- **Scope guard relaxed**: The hard `return fmt.Errorf("scoped network execution
  is pending...")` that blocked ALL device tests when scope hosts were declared
  without a proxy is now a warning+limitation. Phase A adb checks, Phase C Frida
  crawl, and Phase D storage/log checks run regardless. Only Phase B network
  capture remains gated on `ProxyPort > 0`.
- **Decision**: app runs unmodified first when no protections detected; bypasses
  enabled only when static analysis (or adaptive retry) determines they're needed.
  No unnecessary hooks on clean apps.
- All existing tests pass (`devicelab`, `assessment`, `staticx`, `cmd/apkassess`).

### Reproduce without Daybreak

From the Android repository root:

```sh
go build ./...
go vet ./...
./scripts/test-postgres.sh
go test -race ./internal/assessment ./internal/devicelease ./internal/devicelab ./cmd/apkassess
python3 -m unittest discover -s scripts -p 'test_*.py'
```

From `web/`: `npm run typecheck` and `npm test`.

When the authorized emulator is available, run the protected local benchmark
and score the newly printed report directory (do not reuse a historical score):

```sh
./run-android.sh assess --apk validation/corpus/allsafe.apk --device 127.0.0.1:6555
python3 scripts/score_allsafe.py reports/<new-id>/assessment.json
python3 scripts/check_assessment_secrets.py --facts reports/.cache/static/d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9/facts.json reports/<new-id>/assessment.json reports/<new-id>/final.md reports/<new-id>/final.html
```

The benchmark requires Go, Python 3, local Docker/PostgreSQL for isolated DB
tests, Node for frontend/observer tests, ADB, aapt2, jadx, a rooted authorized
emulator and a matching Frida client/server. PDF export requires a supported
local converter. The CLI and test harness clean up their owned processes; they
do not stop development DB containers, other applications or preexisting Frida.
