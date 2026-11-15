# ARTEX Android — Setup & Prerequisites

This directory is self-contained and location-independent: it can be copied or
moved to any path on any machine and built/run without editing source, provided
the external tools below are installed and on `PATH`. All tool lookups go through
`PATH` (Go `exec.LookPath`, Python `shutil.which`); none are hardcoded to an
absolute install location.

## Build toolchains

| Toolchain | Minimum known-good | Used for |
|-----------|--------------------|----------|
| Go        | 1.26 (built with go1.26.8) | the `androidlab`/`apkassess` binaries and all Go packages |
| Node.js   | 26 (built with v26.7.0)    | the `web/` Next.js UI (`web/package.json`) |
| Python    | 3.11+ (validated on 3.14.4)| `vapt/`, `validation/`, `scripts/` helpers |
| Java (JDK)| 17+ (validated on OpenJDK 26) | runs the jadx/apktool jars used by `validation/differential.py` |

Build the binaries:

```sh
./build.sh                      # multi-arch release build of ./cmd/artex -> androidlab
go build -o apkassess ./cmd/apkassess   # the autonomous one-shot assessor
```

## External runtime binaries

These are **not** vendored — install them from your OS/package manager and keep
them on `PATH`. Versions below are what this tree was validated against; the
tool degrades gracefully (preflight warnings) when an optional one is missing.

| Binary | Validated version | Required? | Purpose |
|--------|-------------------|-----------|---------|
| `adb` (Android platform-tools) | 1.0.41 | required for device runs | device control, install, logcat, reverse-proxy |
| `aapt2` | 2.19 | required | APK manifest/badging extraction |
| `jadx` | 1.5.6 | required | DEX → Java decompilation (static analysis) |
| `apktool` | 2.7.0 | required | resource/manifest decoding |
| `frida` (client) | 17.22.2 | optional | dynamic hooks (crypto/pinning/root/pin detection) |
| `frida-server` | match client major | optional | pushed to device for instrumentation |
| `google-chrome` or `chromium` | current stable | optional | HTML→PDF report rendering, CDP smoke |
| `openssl` | 3.x | optional | certificate/key inspection |
| `nuclei` | v3.11.1 | optional | templated network checks |
| `apksigner` | build-tools | optional | signature verification |
| `rg` (ripgrep) | current | optional | fast source grep in agent flows |
| `docker` + `docker compose` | current | optional | containerized DB/deploy and smoke tests |

PostgreSQL (server mode): the `server` package and its integration tests need a
reachable PostgreSQL. Tests **skip** automatically when no database is configured.

## Environment variables (all optional — sensible relative defaults)

| Variable | Default | Effect |
|----------|---------|--------|
| `ANDROIDLAB_CONFIG` | `./internal/config.json`, else `<binary dir>/config.json` | config file location |
| `ANDROIDLAB_SKILL_DIR` | `<binary dir>/skills` | skills directory |
| `ANDROIDLAB_PG_DSN` | from config file `database` | PostgreSQL DSN |
| `ANDROIDLAB_SESSION_CONTAINERS` | auto (the `android-lab-pg` convention) | override dev-DB container names for `scripts/session.py` |
| `JADX_LIB_DIR` | auto-detected from the `jadx` on `PATH` | jadx jar directory for `validation/differential.py` |
| `APKTOOL_LIB_DIR` | auto-detected (`/usr/share/apktool`, …) | apktool jar directory for `validation/differential.py` |

## Python dependency manifests

Each Python area declares its own dependencies; there is no single shared venv.

| Area | Manifest | Install |
|------|----------|---------|
| `vapt/` | `vapt/requirements.txt` (min) + `vapt/requirements.lock` (pinned) | `pip install -r vapt/requirements.lock` |
| `validation/` | `validation/requirements.lock` (pinned) | `pip install -r validation/requirements.lock` |
| `scripts/` | `scripts/requirements.txt` | `pip install -r scripts/requirements.txt` |

## Quick check

```sh
go build ./... && go vet ./... && go test ./...   # server DB tests skip without PostgreSQL
python3 -c "import vapt"                           # from this directory
```

## Autonomous mobile assessment — local LLM + Burp MCP

The assessment agent can run self-reasoning on a **local LLM** and drive traffic
capture/analysis through **Burp Suite's MCP Server** — no third-party calls.

### Local LLM (on-prem model)
```sh
ANDROIDLAB_LLM_PROVIDER=local                        # OpenAI-compatible, no API key
ANDROIDLAB_LLM_BASE_URL=http://localhost:11434/v1    # Ollama default; or llama.cpp/LM Studio/vLLM
ANDROIDLAB_LLM_MODEL=<pulled model>                  # e.g. qwen3-27b
```

### Burp MCP (autonomous traffic capture + replay)
1. In Burp Suite, install the **MCP Server** extension (BApp) and enable it on the
   **MCP** tab (default `http://127.0.0.1:9876`, SSE).
2. Add a Proxy listener with **"Support invisible proxying"** so proxy-unaware apps
   (Flutter) are captured; trust Burp's CA on the device; route device traffic to it
   (Android: iptables DNAT to the listener; iOS: DNS-redirect to a Burp-invisible host).
3. Point the tool at it:
   ```sh
   ANDROIDLAB_BURP_MCP_URL=http://127.0.0.1:9876   # default
   ```
The agent exposes `mobile_capture_status` (verify the connection), `mobile_list_bypasses`
(root/pinning/Flutter-TLS defeats + Frida script), `mobile_traffic_history` (read decrypted
exchanges), and `mobile_traffic_replay` (replay for authz/IDOR).
