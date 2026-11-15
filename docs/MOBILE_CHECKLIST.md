# Mobile assessment checklist

Every Android asset receives 91 procedures across 13 sections in **Android → Assessments → Security checklist**. The catalog is embedded in `internal/mobiletest/catalog.json` and versioned by `mobiletest.Version`.

**Run Assessment** performs bounded offline APK inspection before the existing installation, launch, runtime observation and API follow-up. Offline APK triage also populates the checklist. Existing assessments receive the checklist on their next read; run triage or an assessment to collect new evidence.

Bundled technology detection covers DEX/JVM, Kotlin metadata, Compose references, Flutter/Dart, React Native/Hermes, Cordova, Capacitor, .NET/Xamarin/MAUI, Unity/IL2CPP and native ELF libraries. A marker may come from a dependency. It does not establish the source language of business logic, recover compiled logic, verify package versions, or prove vulnerability.

Static inspection reads at most 16 MiB per eligible entry and 64 MiB total without extracting or executing code. Profiles retain marker provenance, manifest flags, deep-link declarations, possible debug artifacts, inspected byte counts and limitations. Absence of markers never proves absence of a feature.

The fixed runtime observer also records metadata for Activity `FLAG_SECURE`, clipboard set/clear operations, native input types, Keystore provider requests, random API invocations, BiometricPrompt calls and loaded runtime modules. It collects no clipboard/field values, random bytes or key material through these hooks. Events apply only to supported APIs reached after attachment. Flutter/custom-rendered fields and native/managed business logic require separate instrumentation and manual validation.

## Procedure results

- `not_tested`: no current procedure-specific evidence; prerequisites remain listed.
- `observed`: partial static/runtime evidence or an unreviewed test result.
- `inconclusive`, `blocked`, `not_performed`: recorded attempt or coverage gap.
- `passed`, `failed`: current reviewed procedure-specific evidence records `no_issue` or `vulnerable`, respectively, for the same APK asset, environment and revision. These describe recorded conditions only.

A completed job, silent hook, library marker or generic security-objective result cannot pass a procedure. Newer inconclusive observations supersede older passes. Evidence outside the freshness window is retained for review but cannot complete coverage. Every Android asset has an independent checklist, and incomplete procedures prevent an asset being labeled fully tested.

Expand a procedure to inspect its actual steps, MASVS/CWE references, layer, prerequisite context and linked evidence. **Record procedure result** opens manual test entry with that APK and procedure selected. General manual evidence can also select a procedure. The backend validates the procedure ID against the asset and security objective. The operator must attest that the recorded test was performed or attempted.

Structured coverage imports can supply `control_ids` on each test. Imported results still require explicit evidence review before they can pass a procedure. Reports include the checklist, technology markers, evidence references, statuses and remaining gaps.

## Coverage limits

Catalog inclusion is not automated implementation. Credentialed authentication, OTP, multiple-role authorization, transaction logic, replay/race tests, private-data review, interception, bypass resistance, compiled-code reversal, signing verification and dependency advisories need their specified tools, accounts, workflows and scope. These remain untested until evidence is recorded. Report mappings guide review; they do not certify regulatory compliance or establish the applicability of a finding automatically.

## APK test accounts

After creating an assessment, open **Android runtime → APK test accounts → Add APK account**. Select an APK and enter an account label/role, username (or email/phone), and app password. No website or API origin is required. You can save multiple account labels, replace a saved account using **Update**, and remove it with **Remove**. Account changes wait until any active assessment execution finishes.

Credentials are encrypted in the assessment's existing secret store. Assessment responses expose only the account ID, role and APK binding; usernames and passwords stay hidden. APK accounts are a separate credential kind and cannot be used as HTTP Basic credentials by API probes. Saving an account neither runs a login flow nor marks authentication procedures as passed. Sign in on the emulator during observation; automatic app login is not implemented.
