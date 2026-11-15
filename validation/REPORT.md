# Android parser and API-check validation — 2026-10-21

**Result: the current implementation does not meet full parser-equivalence, selection-recall, or independent scanner-agreement expectations.** This is a measured baseline, not a clean bill of health. Scanner/parser behavior was frozen during measurement; no missing decoder, endpoint mapping, or new scanner was added to improve the scores. The only production behavior changed in this pass is the final-report validation gate.

| Measure | Result | Denominator |
|---|---:|---|
| Parser exact field-group agreement — Apktool | **75%** | 15 / 20 |
| Parser exact field-group agreement — JADX | **75%** | 15 / 20 |
| Parser exact field-group agreement — Androguard | **75%** | 15 / 20 |
| Parser combined agreement | **75%** | 45 / 60; missing capabilities count as failures |
| Relevant-reference selection recall | **50%** | 2 selected / 4 manually relevant records in original inventory |
| Scope-eligible selection recall | **66.7%** | 2 / 3, excluding shared third-party httpbin |
| Correct skip dispositions | **93.9%** | 31 / 33 skipped records |
| Mutation target detection | **87.5%** | 7 / 8 deliberate changes |
| Complete mutation fact-delta agreement | **62.5%** | 5 / 8, including DEX string-table changes |
| Live Allsafe API finding confirmation | **100%** | 1 confirmed / 1 candidate |
| Controlled HTTP behavior reproduced through ZAP | **100%** | 4 / 4; original requests replayed, response bodies identical |
| ZAP automatic alert agreement | **50%** | 2 / 4 categories, including an active XSS follow-up |
| ZAP passive alerts on the original exchanges alone | **25%** | 1 / 4 categories |

Do not merge these into a production precision claim. The live finding population contains just one case; the four HTTP cases are synthetic controlled fixtures, not four additional Allsafe vulnerabilities. If a combined strict confirmation number is required, it is **3/5 = 60%**, but that mixes different populations and includes a new XSS validation request.

## Parser corpus and method

Four APKs were processed by all four parsers:

| APK | Build pipeline / provenance | Obfuscation | DEX files |
|---|---|---|---:|
| aapt1-smali-multidex | Locally generated AAPT1 + Smali fixture | Off | 2 |
| aapt2-d8-unobfuscated | Locally generated AAPT2 + javac + D8 fixture | Off | 1 |
| aapt2-r8-obfuscated | Same Java source and resources, AAPT2 + R8 | On; mapping proves `lab.validation.EndpointStrings → a.a` | 1 |
| allsafe | User-selected training APK; original build provenance unverified | Unknown; not counted as the verified obfuscated case | 7 |

The first three are unsigned structural parser fixtures, not installed/runnable application acceptance tests. Allsafe is the real application sample. This is a small corpus; it does not establish compatibility with every Android build system, OEM format, split-install layout, malformed APK, or DEX version. Multidex meets the requested multidex/split requirement; no split APK was tested.

Versions: Apktool **2.7.0-dirty** (installed Debian build), JADX **1.5.6**, Androguard **4.1.4**, Smali **2.5.2**, R8/D8 **8.3.37**, AAPT1 **0.2-debian**, AAPT2 **2.19-debian**. Exact versions, R8 checksum, ZAP image digest and APK hashes are retained in [tool versions](results/tool-versions.json) and [corpus manifest](results/corpus.json).

Each reference CLI decodes its own manifest/resources. Full DEX string tables are read through Apktool's bundled **dexlib2**, JADX's own **DexReader/SectionReader**, and Androguard's **DEX** parser. The Java adapter invokes separate decoders; it does not implement a fourth shared DEX decoder. XML field normalization is shared only after each tool has independently decoded binary data. Go's diagnostic test invokes the existing production `Analyze`, `parseManifest`, and `DiscoverApplicationURLs` code. It does not add a substitute parser.

Five predeclared field groups were compared: permissions; component kind/name/exported/permission; six manifest application flags; complete DEX strings; and embedded HTTP(S) URL tokens. Component names and omitted-exported defaults are normalized consistently; flags preserve explicit/omitted distinction. URL query **names** are retained, values and fragments removed; Android/W3C namespace URLs are excluded consistently. URLs are gathered from each reference's decoded strings/resources; no network requests are used for parser comparison.

“Exact field-group agreement” means the whole normalized group matches for one APK and one reference. It is **not** a percentage of all individual strings, nor an APK-level all-fields pass rate. There are `4 APKs × 3 references × 5 groups = 60` comparisons. The three references agree with each other on **60/60** pairwise field-group comparisons. Missing Go fields are failures, not removed from the denominator.

| Field group | Exact comparisons | Interpretation |
|---|---:|---|
| Permissions | 12 / 12 | Exact sets |
| Components | 12 / 12 | Kind, normalized name, effective exported state and permission |
| Manifest flags | 12 / 12 | debuggable, allowBackup, usesCleartextTraffic, testOnly, extractNativeLibs, supportsRtl |
| Complete DEX strings | **0 / 12** | Go does not expose a complete DEX string table; this is missing capability, not proof of incorrectly decoded strings |
| Embedded URL tokens | **9 / 12** | Three Allsafe template strings absent from Go output |

Allsafe has 116,327 distinct decoded DEX strings in each reference output. Go's URL scanner cannot stand in for that inventory. The three URL disagreements are Firebase App Check templates containing `%s` substitutions (`exchangeDebugToken`, `exchangePlayIntegrityToken`, `generatePlayIntegrityChallenge`). Go rejects them as invalid literal URLs; the reference adapter retains them as embedded templates. They should not be sent as raw HTTP URLs. This is an inventory/normalization boundary, not proof of a binary decoder corruption. The difference remains counted and logged.

The R8 fixture's literal URL is extracted, but app-class attribution is lost because its class is outside the manifest package after obfuscation. The URL-set agreement score does not validate app ownership attribution or automatic test eligibility.

Artifacts: [field comparisons](results/differential/comparisons.json), [summary](results/differential/summary.json), [every disagreement](results/differential/disagreements.jsonl), [normalized facts](results/differential/facts.json), [commands and exit codes](results/differential/commands.json). There are 349,110 disagreement rows: 349,089 per-reference missing DEX-string facts, 12 unsupported-field markers, and 9 URL-template differences. Repeated comparisons against three references are intentionally retained, not counted as independent bugs.

## Manual audit of all 33 skipped references

The [33-row audit](results/skip-audit.csv) records the original reason, a manually assigned correct/incorrect coverage disposition, rationale, and decoded source file/line evidence for every row. The labels were authored from code/resource inspection; they are not the output of the existing domain blacklist.

Thirty-one are correctly excluded from assessment follow-up: SOAP/XMP namespaces, license text, author profiles, documentation/support links, OAuth scope identifiers, library placeholders, and a generic Google+ SDK URI without an attributable Allsafe resource.

Two should not have been discarded as irrelevant:

1. **`https://httpbin.io/json`** — `CertificatePinning.smali` passes this URL into `OkHttp Request.Builder.url`, builds a call and enqueues it. It is real app-used traffic. It should remain an external dependency/testing limitation. This finding does **not** authorize vulnerability scanning of shared httpbin infrastructure.
2. **`https://firebasestorage.googleapis.com/v0`** — the SDK base connects to actual app usage. `InsecureProviders.smali` calls `getReferenceFromUrl("gs://allsafe-8cef0.appspot.com/readme.txt")`, and resources declare that bucket. Probing the generic `/v0` root would be inappropriate; dismissing the reference loses a concrete app-bound Storage target that needs resolution and assessment. No new storage probe was performed in this pass.

The metric is deliberately **coverage disposition**, not “is it safe to GET the skipped literal as-is.” With the two originally selected Firebase records, the fixed population has four relevant records: `TP=2`, `FN=2`, so recall is **2/(2+2)=50%**. Removing shared third-party httpbin from the eligible-testing denominator gives **2/3=66.7%**. Skip-decision accuracy is **31/33=93.9%**, which must not be mislabeled recall.

The original inventory separately counts the Firebase root and derived REST route. These are not independent backend families. This metric measures only the original 35-row population, not all endpoints the application might construct. In particular, the `gs://` storage object was missed by HTTP-only discovery. See [metric definitions](results/skip-summary.json).

## Firebase candidate resolved

The candidate is now **validated**, high confidence, in the existing assessment. Independent reproduction used one anonymous raw read:

```http
GET /.json?orderBy=%22%24key%22&limitToFirst=1&timeout=5s HTTP/1.1
Host: allsafe-8cef0.firebaseio.com
Accept: application/json
```

Observed HTTP **200**, **43 bytes**, complete JSON with an actual **32-character string at the training challenge's `flag` key**. No Authorization, Cookie, auth query parameter, or application credential was supplied. No writes or further data traversal were performed. This confirms real anonymous data read capability; it does not establish exposure of real users' production information.

The unredacted request/response is retained locally with mode 0600 at `Android/data/validation-private/firebase-raw.http`. Its response SHA-256 is `3d0d0150bc71a7bf2b1e082b25282eb428a5990576b8e76ba99458532a3246be`. The public validation artifact contains only structure/types/lengths. The value itself is not copied into this report.

Finding `a403e2490e711822beee2476` was updated through the normal evidence and validation APIs, with evidence `7cf7fb40ccffc2170791f0be`. See [raw-request metadata](results/firebase-validation.json) and [persisted outcome](results/firebase-persisted-validation.json). The earlier metadata-only observation remains in history; it was not silently replaced.

Going forward, “unconfirmed” means a **candidate signal awaiting independent validation**, or an **inconclusive investigation whose evidence cannot support either confirmation or dismissal**. It is not a deliverable vulnerability status and is never converted to false positive merely to close a report. False positive requires a relevant negative control/evidence. Final report export now rejects unresolved findings with HTTP 409. Explicit review drafts are labeled DRAFT in content and filename. Administrative accepted-risk status alone does not prove the vulnerability, so it also cannot bypass this gate. Allsafe still has nine unresolved static-analysis candidates, so its overall final report remains blocked even though this one live API finding is resolved.

## Controlled mutations

Starting with a clean AAPT1/Smali multidex baseline, generated eight valid APK variants with exactly one planned source-level change: add permission; remove permission; toggle debuggable; toggle one component's exported state; add a receiver; replace a primary-DEX URL; replace a secondary-DEX URL; replace a non-URL DEX string. Each DEX was reassembled with fresh valid checksums; manifests were compiled as real binary AXML.

All three reference tools independently agreed on the expected deltas. Go detected **7/8 target changes with no unexpected changes to its supported fact fields**. It missed the non-URL `clean-marker → changed-marker` replacement. When complete DEX-string deltas are also required, only the five manifest mutations are fully represented: **5/8**. Both URL replacements are seen in URL inventory but absent from a full DEX-string inventory, which Go does not expose.

[Mutation plan](results/mutation-plan.json), [expected versus actual deltas](results/mutation-summary.json), [all mutant differential disagreements](results/mutations/disagreements.jsonl). This is input mutation testing, not a claim about source-code mutation operators or a general mutation-testing score.

## Independent HTTP reproduction with ZAP

The existing four-positive Go unit fixture was recreated as a real localhost HTTP server. The custom runner sent its bounded requests through **ZAP 2.17.0**. Original messages were exported, then re-issued independently using ZAP's `core.sendRequest` API. All four replayed response bodies matched their original bodies exactly. Request/response pairs, alerts and hashes are retained.

| Custom check | ZAP Requester reproduction | ZAP automatic confirmation | Final interpretation |
|---|---|---|---|
| Credentialed origin reflection | Two supplied origins independently reflected with `ACAC: true` | No default alert | Header behavior confirmed; fixture has no protected user data, so credentialed data theft not established |
| Session cookie flags | Session cookie lacks HttpOnly and Secure | **10010: Cookie No HttpOnly Flag** | HttpOnly issue independently corroborated; plain-HTTP fixture does not trigger ZAP's HTTPS-only missing-Secure rule |
| Reflected input | Same inert marker returned unescaped in HTML | **40012: Reflected XSS**, on ZAP's additional active payload | Reflection confirmed; follow-up demonstrates executable injection on the same endpoint, not on the original inert-marker exchange |
| Error leakage | A quote returns `SQLSTATE[42000]`, absent in baseline | No default error-disclosure/SQLi alert | Diagnostic-string observation reproduced; synthetic fixture has no SQL backend, so SQL injection is not confirmed |

Consequently **raw behavioral reproduction is 4/4**, **automatic scanner corroboration is 2/4**, and **passive automatic agreement on the exact original exchanges is 1/4**. These are different measures. CORS and SQLSTATE discrepancies remain recorded; the fixture was not changed to manufacture alerts, and ZAP signatures were not customized to match the Go rules. ZAP's other unrelated CSP/header/SameSite alerts are excluded from this denominator.

Artifacts: [original messages](results/zap-original-messages.json), [independent replays](results/zap-replayed-exchanges.json), [custom checks](results/custom-http-checks.json), [ZAP alerts](results/zap-final-alerts.json), [confirmation summary](results/http-confirmation-summary.json). Active scanning was restricted to the local fixture with only reflected-XSS and non-time-based SQLi rules enabled. No ZAP scan was run against Allsafe's remote backend or third-party services.

## Reproduction and acceptance

See [README](README.md) for commands and prerequisites. [Machine-readable metrics](results/metrics.json) preserve all numerators and denominators. `summarize_results.py --require-full-agreement` intentionally exits 2 for this baseline; it does not report a passing validation gate.

Implementation regression checks and the differential acceptance result are separate: Go race tests and the final-report HTTP integration check pass; the differential/mutation/selection comparison exposes the deficiencies above. Neither a passing application build nor scanner silence changes those measurements.

Primary tool references: [JADX library usage](https://github.com/skylot/jadx/wiki/Use-jadx-as-a-library), [Androguard APK API](https://androguard.github.io/androguard/reference/androguard/core/apk/index.html), [ZAP API](https://www.zaproxy.org/docs/api/), [Firebase REST retrieval](https://firebase.google.com/docs/database/rest/retrieve-data). The actual measured outputs, not tool documentation, determine the scores in this report.

Live verification after rebuild: final Allsafe export returned **409**, explicit draft export returned **200** with a DRAFT heading/filename, and the Firebase finding remained `validated` after restart. Nine static candidates remain unresolved. The production frontend build, TypeScript/Biome, Go race tests, and PostgreSQL report-gate integration passed. Temporary ZAP and fixture services were stopped after evidence capture.
