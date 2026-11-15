# Controlled assessments

This is the first coverage-oriented implementation of the supplied Android/web/API assessment specification. It preserves the existing Go/PostgreSQL/Next.js architecture instead of introducing a second Python/FastAPI stack. Discovery, deterministic planning, approved execution, evidence, validation and reporting are separate components.

## Capability boundary

| Capability | Current behavior |
|---|---|
| Scope manager | Consumer/admin web URLs, API URL prefixes, exact uploaded APKs, environment/revision, roles, credentials, restrictions and business rules |
| Previous reports | Structured JSON tests with provenance, actual observations and context; explicit human review required before reuse |
| API discovery | APK app-class const-string attribution, compiled resource strings, runtime OkHttp/URLConnection request methods, OpenAPI/HAR/MobSF imports |
| API security agent | Automatic discovery followed by bounded transport, CORS, cookie, error-disclosure, HTML-reflection, query-error and Firebase metadata checks on eligible endpoints |
| Web testing | Scoped GET/HEAD observations and app-endpoint security probes; multi-account authorization, state-changing workflows and business rules require appropriate session/fixture context |
| APK testing | Offline manifest triage, archive inventory and literal URL discovery without executing APK code |
| Scanner integration | ZAP traditional JSON and matching MobSF static JSON imports; no active scanner submission/launch adapter yet |
| Planning | Persistent goal/planner/worker lifecycle, structured tool-free model proposals with deterministic fallback, and evidence-driven replanning; see [task flow](ANDROID_TASK_FLOW.md) |
| Execution policy | Exact origin/path scope, exclusions, fixed action schemas, rate/budget, one active action, safety stop, audit and crash recovery |
| Validation | Separate candidate, validated, inconclusive, false_positive, accepted_risk and remediated states with evidence requirements |
| Reporting | Deterministic Markdown drafts; final export is blocked while findings remain unresolved |
| Protection workers | Process-local root/emulator and Java certificate/pin adapters; evidence distinguishes initialization, invocation and connection observation. Native/Flutter-specific checks remain unsupported without matching adapters. |
| Dynamic mobile testing | Persisted jobs on an existing Genymotion/ADB device: APK installation, installed-hash verification, package metadata, launcher execution, PID-filtered logs and a fixed Frida observer; evidence remains separate from verified security coverage |
| Business logic | Documented rules inform planning; execution remains manual and needs evidence of an actual rule violation |

No scan is reported as run merely because an integration format is supported. The AI advisor cannot dispatch actions, change policies, validate a finding or create evidence.

## Scope and credentials

Consumer/admin websites, API base URLs and test account credentials are **optional**. An APK-only assessment supports static triage, installation, launch, log collection and Frida observation with no web/API assets or platform-stored test credentials. Select the uploaded APK and then authorize the test device in **Android runtime**. Sign into the app manually on the emulator if your workflow needs an app session.

For APK-only assessments, an omitted environment defaults to `local-device`, and an omitted implementation revision defaults to the uploaded APK hash (or a deterministic hash of the selected APK set). Explicit context is preserved. **Run API security agent** discovers and tests eligible app endpoints without typed target URLs. Optional web/API inputs add explicit scope and context.

Create an assessment from **Assessments → New assessment**. Approval covers the literal scheme, host, port and path prefix of each URL. A root URL allows that origin's paths; `/api` allows `/api` and its descendants, not `/admin` or `/apievil`. Subdomains, different ports and HTTP/HTTPS variants are distinct. Embedded URL credentials, wildcard targets, dot traversal and ambiguous encoded paths are rejected.

Imported endpoints never alter approved assets. The API-agent action enables a separate `test_discovered_apis` policy: URLs with app-code/resource or actual-request provenance bound to the selected APK become eligible only at their discovered literal paths. SDK/reference strings do not automatically become targets. Exclusions override both explicit and app-derived scope. Policy changes recalculate endpoint scope and coverage decisions.

Free-text restrictions describe assessment context; they are not executable rules. Encode request restrictions in approved URL prefixes, explicit exclusions, the HTTP-observation toggle and numeric policy limits. Requirements that these controls cannot express need manual handling before enabling execution. There is no high-impact/destructive action adapter to enable.

Credentials support bearer tokens or HTTP Basic via the API; the create form provides consumer/admin bearer-token fields. Each credential is bound to an approved origin, and each role/origin pair is unique. Values are encrypted at rest with AES-GCM and assessment-specific associated data. The signing-key identity volume must be backed up with the database. Values are not returned by assessment APIs, passed to the AI planner or written to general reports.

## Evidence sources and API inventory

Supported imports:

- **OpenAPI 3 JSON**: methods, normalized paths, declared security requirements and named parameters. Root, path and operation server/security precedence is respected. Use an absolute fallback base URL for relative servers. Resolve variable servers and path/operation/parameter references before import. YAML and Swagger 2 need conversion; remote references are never fetched.
- **HAR**: request method/URL and parameter names establish observed usage. Request/response bodies, credentials and cookie values do not become inventory or coverage evidence. Actual security-property coverage still needs reviewed tests.
- **Structured coverage**: a `tests` array with `url` + `method` or an existing `subject_id`, `objective`, `role`, `parameters`, `environment`, `revision`, `observed_at`, `outcome`, and actual `observation`/artifact references. See `examples/coverage-report.json`. Generic report prose or a route mention is not sufficient.
- **ZAP traditional JSON**: site alerts/instances become candidate findings with source references. Absence of alerts is never recorded as a passed test.
- **MobSF static JSON**: report `sha256` must match the selected uploaded APK. Supported manifest/code findings remain candidates. URL observations remain method-unknown; a report for another APK is rejected.

The importer deduplicates endpoint records by method + canonical origin + normalized path. Numeric/UUID identifiers and named path variables become `{id}` for inventory comparison. Trailing slash distinctions are preserved. Literal APK URLs retain `UNKNOWN` methods; they are not merged into a known GET/POST route merely because the paths resemble each other. `used_by` captures consuming source assets; `hosted_by` associates endpoints with approved hosting assets without claiming consumer usage.

Known query values are discarded from inventory. Parameters retain names/locations, such as `query:include` or `path:orderId`, for applicability checking.

Every JSON source retains a SHA-256 identifier. The UI sends original JSON text in `raw_json` so whitespace and exact file bytes are preserved for hashing; API clients can also send a parsed object in `data`. Original source JSON is encrypted and saved atomically with source/evidence metadata in PostgreSQL. The **Evidence** tab downloads a redacted copy for inspection. Its bytes intentionally differ from the original checksum. Known credentials, common secret patterns, sensitive header pairs, cookie values and traffic bodies are removed from general downloads. Redaction is not a substitute for reviewing unknown sensitive content before distribution.

The built-in archive reader preflights central-directory structure before allocating entry metadata. It caps APKs at 256 MiB and central-directory metadata at 16 MiB. ZIP64, multidisk and unsupported offset layouts are rejected explicitly.

APK discovery reads at most 8 MiB per eligible entry, 64 MiB total, and emits at most 2,000 URL observations. Each observation records its APK-entry location and source hash. No APK execution, archive extraction or discovered-host contact occurs. Constructed URLs, obfuscated class ownership, runtime-only routes and complete control-flow semantics still require runtime or additional evidence. Compiled resource string pools are decoded, including UTF-16 strings.

## Deterministic planning

Each plan row identifies a subject, objective and role. Applicable coverage requires:

1. The same subject and security property.
2. The same account role and parameter set.
3. The current declared environment and implementation revision.
4. A past observation within the configured freshness window.
5. An explicit reviewer and a substantive `no_issue` or `vulnerable` outcome.

Historical report imports are unreviewed. Reviewing them does not repair a missing context, mismatched role, stale date or different implementation. The newest applicable result is selected. Known vulnerable results prompt targeted retesting; no-issue results support reuse only under the recorded conditions. Observed HTTP headers, route discovery, scanner silence and an analysis tool completing do not establish substantive coverage.

Planner decisions are `test`, `review_evidence`, `reuse_evidence`, `retest`, `needs_context`, `review_discovery`, and `blocked`. Business logic needs documented expected rules. Mobile storage, tokens, exported components, deep links, cryptography, dependencies, logs and WebViews receive separate checks from web/API properties.

Asset status distinguishes `not_tested`, `coverage_unknown`, `partially_tested` and `tested`. Here, `tested` describes coverage of the defined property/role matrix, not a declaration that the asset is secure. Plan totals count property/role checks, not unique endpoints; each row has one decision, avoiding overlapping headline categories.

Optional AI advice receives a bounded sample of the plan, approved asset metadata, restrictions and business rules. It receives no testing credentials, raw traffic bodies, tool schemas, filesystem primitives, SDK default tools, MCP tools or network-fetch tools. Advice is stored separately from evidence and is excluded from authoritative report findings/coverage. A configured provider is required only for this advisory call.

## Dispatch, durability and safety stops

### APK-to-API security agent

Select **Run API security agent** in the assessment toolbar or **Android runtime**. The persisted job verifies and inspects the approved APK, extracts app-class URL references from DEX instructions and UTF-8/UTF-16 compiled resource strings, merges existing runtime request observations, and selects eligible endpoints for security checks. Manual consumer/admin URLs, API bases, credentials, ADB device selection and an LLM provider are not prerequisites for this job.

The Frida observer now records request methods and URLs from supported OkHttp `execute`/`enqueue` and Android `HttpURLConnection.getInputStream` implementations. URL constructor observations remain method-unknown. Hook initialization and request-object observation do not establish that a remote server received a request. Credentials, body values and query values are not captured by these hooks. Exercise app workflows during the observation window to discover runtime-only endpoints.

Each eligible URL receives fixed read-request checks selected from transport, session-cookie flags, verbose error signatures, and a two-origin credentialed-CORS comparison. A discovered query parameter can receive an HTML marker and quote-error comparison. Generic status changes never confirm injection. App-configured Firebase Realtime Database URLs additionally produce an inferred `/.json` REST route; the specialized check sends only an anonymous `shallow=true` read, retains a count/hash, and does not store key names or database values. API findings start as **candidate**, with source, check, response-prefix hash and remediation. There is no automatic promotion to a confirmed vulnerability or broad passed coverage.

The automatic scope excludes recognized documentation, XML namespaces, SDK examples, social links and generic third-party services. Private/reserved addresses require explicit scope. Every DNS answer is checked before a direct connection, preventing app-controlled hosts from resolving into internal infrastructure; redirects, environment proxies and TLS-validation bypass are disabled. Potentially state-changing route names and observed POST/PUT/PATCH/DELETE requests are retained with a skipped reason rather than replayed. Explicit optional targets can identify internal services when appropriate.

The job uses the same durable request budget/rate, safety-stop counter, audit and cancellation controls as the rest of the assessment. It has a twelve-minute limit, a fifteen-minute lease, and at most twenty concrete endpoints per run. Queued/running jobs share assessment exclusion with device jobs. Completed and skipped checks are persisted as evidence, and encrypted source JSON contains the structured results. Actual SQL-injection exploitation, JavaScript execution, multi-account IDOR and business-logic state transitions are not inferred from these read-only probes. Authenticated probes use supplied origin-bound credentials when available; instrumentation currently records request metadata, not reusable session tokens.

Implementation references: [Android DEX layout](https://source.android.com/docs/core/runtime/dex-format), [Dalvik instruction formats](https://source.android.com/docs/core/runtime/dalvik-bytecode), [Firebase REST reads](https://firebase.google.com/docs/database/rest/retrieve-data).

The dispatcher accepts a current `test_id` and a matching predefined action:

- `apk_triage`: rehash the approved APK, inspect the manifest, collect candidate findings and discover bounded URL literals.
- `http_observe`: only GET/HEAD literal paths in approved scope, only when explicitly enabled. No query values, request bodies, arbitrary headers, redirects, cookie jar, environment proxy or TLS-validation bypass. Credentials are attached only to their bound origin.

Defaults: 10 HTTP attempts/minute, 100 attempts/assessment, stop after 3 consecutive transport/server errors, and 30-day evidence freshness. Limits are validated server-side. One execution is active per assessment, including across multiple backend instances.

Before any network operation, a short PostgreSQL transaction commits the policy decision, execution reservation, request budget and rate timestamp. A cancellation or crash cannot erase that reservation. Network work is bounded and results are committed separately. Request counters count reserved attempts conservatively, including attempts that fail before a response.

HTTP observations store status, selected header-presence/cookie-attribute metadata and a bounded response-prefix hash. Response bodies and credential values are not retained. A failed connection, certificate validation issue or incomplete response is inconclusive/blocked, not a confirmed vulnerability or a successful control test.

If a process exits before a result commits, the persisted execution remains unresolved. After its two-minute reservation expires, a subsequent mutation records it as inconclusive and pauses execution. Resumption requires an explicit policy update. Missing results never become completed coverage.

The inherited shell-capable agents, custom-tool testing, scheduler, automatic MCP discovery and legacy execution routes are disabled by default. The server opt-in `ANDROIDLAB_ENABLE_LEGACY_AGENTS=1` belongs to a separate advanced environment, outside this dispatcher's guarantees; no assessment or model call can switch it on. All Features and System pages are visible in the sidebar, independent of execution permissions. The server continues to enforce the runtime opt-in.

## Live Genymotion runtime

Open an assessment's **Android runtime** tab. **Run Assessment** is the default workflow for whichever uploaded APK and online device the operator selects; it is not tied to an example app. The request names the exact APK asset and serial and authorizes installation, launch, dynamic observation and the existing bounded app-derived API tests. Manual targets and credentials are optional. No separate device-authorization click is needed for this complete workflow; paused assessments must be resumed first.

Each run installs with `adb install -r --no-streaming`, checks the installed SHA-256 against the upload, launches the resolved package activity, verifies process ownership, and attaches the fixed Frida observer for a chosen 30–300 seconds (default 60). Use the app in Genymotion during observation. Existing app data is retained. No automated UI navigation or credential entry occurs; no root/emulator/pinning bypass is attempted.

Dynamic checks record installed debug/package flags, sandbox access limitations, supported HTTP request invocations, cipher creation, WebView settings, preference/file mode flags, TLS exception observations and credential-shaped log patterns. Values from storage and logs are excluded from candidate descriptions. Root ADB access, backup flags and granted permissions are environment/configuration observations; these alone do not confirm vulnerabilities. No hook events and denied data access are inconclusive. Unconfigured authentication, authorization, deep-link, component and business-logic tests are explicitly not performed. Startup before attachment, unsupported/native clients, secondary processes and unvisited screens remain coverage limitations.

When installation and launch succeed, dynamic evidence and the API continuation are committed atomically. The API job uses persisted runtime requests and static discovery, with the existing host/scope, request budget/rate and error-stop policy. An instrumentation limitation can still allow the API stage using the available evidence. Cancellation, policy pause, failed installation/launch or worker interruption prevents automatic continuation. Browser closure does not lose a queued continuation. Parent and child job IDs connect the two stages.

**Advanced: Individual runtime actions** retains the existing single actions (explicit device authorization required):

- **Inspect installed APK**: verify the uploaded file's SHA-256, device state, device/build context, installed package's SHA-256 and package metadata. A different installed build blocks further runtime actions.
- **Install approved APK**: install the exact approved artifact with `adb install -r --no-streaming`, preserving existing application data, then verify the installed hash. Split APK installations are unsupported.
- **Launch and collect logs**: resolve the package's launcher, launch that component without arbitrary intents/extras, verify the exact process's PID ownership, and collect up to 200 PID-filtered log lines. Logs are not cleared globally.
- **Attach Frida observer**: attach to the verified running package PID for ten seconds. The embedded script records process metadata, initializes URL-construction and cipher-algorithm observations, and then detaches. Interact with the app during that window to produce observations. It emits no request/response bodies or key material and performs no certificate bypass. Missing events do not prove a control is secure.

Both the host `frida` CLI and a compatible server on the emulator must be available. An installed executable or successful process listing alone does not prove attachment is ready. The supplied Genymotion device already contained `/data/local/tmp/frida-server` version 17.22.2; it was started on the emulator's **127.0.0.1:27042**, through the existing ADB connection. It must be restarted if the emulator is rebooted. No emulator was created, wiped, or globally reconfigured.

Jobs live in PostgreSQL, survive browser reloads, and expose progress, terminal status and cancellation. Unique database constraints allow only one queued/running job per device and assessment across backend instances. Individual runtime actions have a 150-second execution limit. Dynamic runs allow their observation duration plus 150 seconds for device work; the worker lease adds 30 seconds. API jobs retain their separate twelve-minute limit and fifteen-minute lease. Queued jobs can resume on backend startup; expired running jobs become **inconclusive**, pause the assessment and are never automatically replayed. Job completion, encrypted artifacts, evidence and audit commit in one transaction. **Cancel job** requests cancellation; **Stop assessment** also pauses further actions. Partial results remain distinguishable from completed observations. Cancellation detaches host tooling; it does not uninstall the app or force-stop the device.

Runtime results are encrypted source JSON with original hashes; authenticated downloads apply credential redaction. General assessment records contain provenance and summaries rather than raw logs. Runtime metadata does not automatically satisfy an authorization, TLS, logging-confidentiality or business-logic test. URL constructor events retain **UNKNOWN** methods; request-hook events retain their observed method. Both preserve their source and APK binding, and only eligible app-request/code/resource evidence can enter API-agent scope.

The device must use your approved test-network configuration. These adapters constrain the selected APK and ADB/Frida actions, but they do not apply the HTTP dispatcher's origin/rate restrictions to traffic generated by the APK itself. Burp/proxy provisioning, automatic private-storage extraction, Objection scenarios, TLS/pinning validation, and arbitrary workflow exploitation are not part of these fixed actions.

The current Allsafe assessment uses package `infosecadventures.allsafe` on Genymotion `127.0.0.1:6555` (Android 11/API 30, x86_64). Its original APK was copied from that selected package, uploaded, and compared with the installed SHA-256 before observation. See [runtime verification](ANDROID_VERIFICATION.md) for the actual outcomes.

## Validation and remediation

Scanner findings and operator candidates start as `candidate`; scanner severity does not confer confirmation. A manual record is explicitly labeled an operator attestation and requires the operator to confirm that it accurately describes an actual test or attempted/blocked check.

To validate, supply reviewed current `vulnerable` evidence matching every affected subject, role, parameter set and security property. An admin-role test cannot confirm a consumer authorization failure. False-positive and remediation verdicts require appropriate reviewed `no_issue` evidence; it must be newer than matching vulnerability evidence. Remediation also requires a previously validated finding. Formal risk acceptance requires an authenticated operator rationale and audit entry.

“Unconfirmed” means a candidate awaiting independent validation or an inconclusive investigation. It never means a confirmed vulnerability or a false positive. Final report export returns HTTP 409 while any finding is outside `validated`, `false_positive`, or `remediated`; administrative risk acceptance alone cannot bypass this evidence gate. An explicit `?draft=1` exports a review copy labeled DRAFT in its contents and filename.

The finding's severity remains independent from validation confidence/status. Candidate potential impact and verified impact must be interpreted separately. Imported role-unknown candidates need an explicit affected role before confirmation. Out-of-scope findings cannot be confirmed in the current assessment.

A deployment/build change requires fresh assessment context and evidence. Current scope/artifact bindings are fixed; use a new assessment for changed APKs, hosts or implementation revisions. Automatic cross-version finding migration and remediation-job orchestration remain future work. Same-context retest evidence and verdicts are supported, but no retest is executed just by changing a status.

## Reports and metrics

The Markdown report is generated from stored state, without an LLM. It includes approved assets, context/restrictions, endpoint inventory, unique confirmed finding totals by severity, candidates and validation details, property/role decisions, source/evidence references, execution history and policy audit. Shared routes are deduplicated; distinct underlying issues are not automatically merged based on a vague title similarity.

Interpret asset/endpoint/property coverage separately. Inconclusive, blocked and not-performed observations remain distinguishable from vulnerable and no-issue results. No runtime, scanner or manual test is claimed completed without a corresponding execution/evidence record. A zero-finding report can still have substantial coverage gaps.

The current UI reports inventory, reusable-property checks, review gaps and validated/candidate totals. Full longitudinal precision, false-positive, duplicate-rate, retest-success and known-vulnerable-app benchmarking dashboards are not implemented yet; reporting only finding counts would not establish effectiveness.

## Next implementation phases

1. Add configured MobSF/ZAP execution clients and an isolated job queue, with tool-specific scope/rate controls and verified result retrieval. Import support alone is not an executable scanner integration.
2. Extend the implemented ADB/Genymotion/Frida runtime jobs with approved proxy traffic collection, private-storage checks and fixed Objection scenarios; record pinning/interception and tool limitations accurately.
3. Add bounded authenticated API authorization scenarios and explicit sensitive-action approvals. Preserve test-account separation and controlled data fixtures.
4. Add workflow-specific business-logic scenarios using confirmed rules, plus version-aware remediation mapping and formal longitudinal metrics against known-vulnerable applications.

Reference formats: [OpenAPI 3](https://spec.openapis.org/oas/v3.0.3), [ZAP traditional JSON](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/), [ZAP API](https://www.zaproxy.org/docs/api/), and [MobSF API routes](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/urls.py). Android behavior references remain in `skills/android-security/SKILL.md`.

## Differential validation baseline

The measured 2026-10-21 baseline is in [validation/REPORT.md](../validation/REPORT.md), with reproducible corpus/mutation runners, every disagreement, the 33-reference manual audit, raw HTTP reproduction through ZAP, and separate agreement/recall/confirmation denominators. Full DEX string extraction and automatic scanner parity have not passed this validation.
