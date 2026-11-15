# Reproduce the validation

Read [REPORT.md](REPORT.md) for results and definitions. This directory is a validation harness, not a new production scanner. Run from the ARTEX repository root unless noted.

Prerequisites used locally: `apktool`, `jadx`, `smali`, `aapt`, `aapt2`, a JDK, Python venv, Go, Docker. The scripts use the installed JADX jar at `/home/madan/.local/share/jadx/lib/jadx-1.5.6-all.jar`, Apktool libraries at `/usr/share/apktool/`, Android framework resources at `/usr/share/android-framework-res/framework-res.apk`, and the approved Allsafe APK at `/tmp/androidlab-allsafe.apk`. Adjust these paths for a different host. The fixture builder locates javac next to the resolved java executable. No APK is installed or executed by these scripts.

## Parser comparison and mutations

```bash
python3 -m venv Android/validation/.venv
Android/validation/.venv/bin/pip install -r Android/validation/requirements.lock
mkdir -p Android/validation/tools
curl -fL https://dl.google.com/dl/android/maven2/com/android/tools/r8/8.3.37/r8-8.3.37.jar -o Android/validation/tools/r8.jar
# Expected R8 SHA-256: 59753e70a74f918389cc87f1b7d66b5c0862932559167425708ded159e3de439
/home/madan/BurpSuite/jre/bin/javac -cp '/home/madan/.local/share/jadx/lib/*:/usr/share/apktool/*' Android/validation/DexStrings.java
python3 Android/validation/build_corpus.py
Android/validation/.venv/bin/python Android/validation/differential.py
python3 Android/validation/mutations.py
Android/validation/.venv/bin/python Android/validation/differential.py Android/validation/work/mutations/corpus Android/validation/results/mutations
python3 Android/validation/summarize_mutations.py
python3 Android/validation/audit_skips.py
```

Corpus hashes identify the measured files, not a claim of bit-for-bit reproducible ZIP timestamps. `results/differential/commands.json` records the actual reference tool commands and exit codes. CLI tool resource/DEX logs and decoded outputs remain beside the normalized facts. The Go diagnostic export lives in `androidapk/differential_export_test.go` and skips unless both corpus environment variables are supplied. Unsupported fields must stay null, not fabricated using reference-tool output.

The manual skip labels are fixed in `audit_skips.py`; rerunning regenerates the cited evidence locations, not a new independent human review. Review the labels again if the APK hash changes. The historical 33-row population comes from `Android/data/api-agent-verification.json`.

## Independent HTTP checks

Start the exact pinned ZAP image and the local fixture in separate terminals:

```bash
docker run --rm --name androidlab-validation-zap --network host ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6 zap.sh -daemon -host 127.0.0.1 -port 18090 -config api.disablekey=true -config autoupdate.checkOnStart=false
python3 Android/validation/http_fixture.py
```

Wait for `http://127.0.0.1:18090/JSON/core/view/version/` to return. ZAP first startup takes around a minute. Then, from `Android/`:

```bash
API_ZAP_VALIDATION_OUTPUT="$PWD/validation/results/custom-http-checks.json" go test ./apicheck -run '^TestIndependentZAPFixture$' -count=1
```

Use `python3 Android/validation/zap_collect.py` from the repository root to export the original custom-run exchanges and run only ZAP reflected-XSS/SQLi rules against the localhost fixture. Then run `python3 Android/validation/zap_reproduce.py` to replay the originals with ZAP Requester and compare results. Never substitute remote targets in this fixture runner. Raw fixture messages contain only deliberately synthetic cookie values. ZAP's extra synthetic site-tree message is excluded from the four-request replay denominator.

## Firebase validation and final report state

`validate_firebase.py` performed the one bounded anonymous Allsafe request described in the report. Re-running contacts that backend again, so it is deliberately excluded from the offline corpus and aggregation commands. It retains at most 4096 response-body bytes, does not follow redirects, and stores the raw observation with mode 0600 under ignored application data. `record_firebase.py` used the existing local signing key in memory to call the normal evidence/validation APIs without changing the user's password or persisting a token. It refuses to promote a response without positive evidence. Repeated recording is idempotent after validation.

The backend's final-report route returns 409 while any finding remains unresolved. `?draft=1` explicitly exports a labeled review copy. Unit and PostgreSQL HTTP tests exercise the gate. Remaining inconclusive results are blockers, never auto-dismissed as false positives.

## Metrics and strict gate

```bash
python3 Android/validation/summarize_results.py
python3 Android/validation/summarize_results.py --require-full-agreement
```

The second command **currently exits 2**, as expected from the measured deficiencies. It should not be represented as a passing check. `results/metrics.json` contains the denominators for parser agreement, selection recall, mutations, and the separately reported live/fixture confirmations. No production vulnerability precision estimate is made from these small samples.
