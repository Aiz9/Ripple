#!/usr/bin/env bash
# install-apk-tools.sh — provision the external tooling the Android APK
# pentest workers can use. Every tool is OPTIONAL: each worker degrades
# gracefully when its tool is missing (SAST falls back to built-in regex
# scanning, SCA falls back to the OSV HTTP API, etc.). This script just makes
# the richer path available and is safe to re-run.
#
# Usage:
#   scripts/install-apk-tools.sh            install everything it can
#   scripts/install-apk-tools.sh --check    report presence only, install nothing
#   scripts/install-apk-tools.sh <tool>...  install only the named tools
#
# Tools: apktool jadx apksigner semgrep trufflehog gitleaks osv-scanner \
#        trivy dependency-check mobsf frida objection
#
# It never installs a system package manager and never runs a remote script
# through a pipe to a shell. Where a tool has no distro package, it fetches a
# pinned release artifact over HTTPS into ~/.local/bin.
set -u

BIN_DIR="${APK_TOOLS_BIN:-$HOME/.local/bin}"
CHECK_ONLY=0
TOOLS_ALL="apktool jadx apksigner semgrep trufflehog gitleaks osv-scanner trivy dependency-check mobsf frida objection"
REQUESTED=""

for arg in "$@"; do
	case "$arg" in
		--check) CHECK_ONLY=1 ;;
		-h|--help) sed -n '2,25p' "$0"; exit 0 ;;
		-*) echo "unknown flag: $arg" >&2; exit 2 ;;
		*) REQUESTED="$REQUESTED $arg" ;;
	esac
done
TOOLS="${REQUESTED:-$TOOLS_ALL}"

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf '[apk-tools] %s\n' "$*"; }
warn() { printf '[apk-tools] WARN: %s\n' "$*" >&2; }

report() {
	log "tool availability:"
	for t in $TOOLS_ALL; do
		if have "$t"; then printf '  %-18s present (%s)\n' "$t" "$(command -v "$t")"
		else printf '  %-18s MISSING\n' "$t"; fi
	done
}

if [ "$CHECK_ONLY" -eq 1 ]; then
	report; exit 0
fi

mkdir -p "$BIN_DIR"
case ":$PATH:" in
	*":$BIN_DIR:"*) : ;;
	*) warn "$BIN_DIR is not on PATH; add it to your shell profile: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

# pkg installs via the first available system package manager (best effort).
pkg() {
	if   have apt-get; then sudo apt-get update -qq && sudo apt-get install -y "$@"
	elif have dnf;     then sudo dnf install -y "$@"
	elif have pacman;  then sudo pacman -S --noconfirm "$@"
	elif have brew;    then brew install "$@"
	else return 1; fi
}

# pipx/pip install for Python tools.
pyinstall() {
	if have pipx; then pipx install "$1"
	elif have pip3; then pip3 install --user "$1"
	else return 1; fi
}

# fetch <url> <dest> downloads over HTTPS to an executable file.
fetch() {
	url="$1"; dest="$2"
	if have curl; then curl -fsSL "$url" -o "$dest"
	elif have wget; then wget -qO "$dest" "$url"
	else return 1; fi
	chmod +x "$dest"
}

ARCH="$(uname -m)"; OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$ARCH" in x86_64|amd64) GOARCH=amd64 ;; aarch64|arm64) GOARCH=arm64 ;; *) GOARCH="$ARCH" ;; esac

install_one() {
	t="$1"
	if have "$t"; then log "$t already present"; return 0; fi
	log "installing $t ..."
	case "$t" in
		apktool|jadx|apksigner)
			pkg "$t" || warn "$t: install via your SDK/distro (apt: apktool jadx; apksigner ships with Android build-tools)" ;;
		semgrep)   pyinstall semgrep || warn "semgrep: needs pipx or pip3" ;;
		mobsf)     warn "mobsf: run via Docker — docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest" ;;
		frida)     pyinstall frida-tools || warn "frida: needs pipx or pip3" ;;
		objection) pyinstall objection || warn "objection: needs pipx or pip3" ;;
		trufflehog)
			fetch "https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.6/trufflehog_3.82.6_${OS}_${GOARCH}.tar.gz" "$BIN_DIR/trufflehog.tgz" \
				&& tar -xzf "$BIN_DIR/trufflehog.tgz" -C "$BIN_DIR" trufflehog && rm -f "$BIN_DIR/trufflehog.tgz" \
				|| warn "trufflehog: fetch failed; see https://github.com/trufflesecurity/trufflehog/releases" ;;
		gitleaks)
			fetch "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_${OS}_${GOARCH}.tar.gz" "$BIN_DIR/gitleaks.tgz" \
				&& tar -xzf "$BIN_DIR/gitleaks.tgz" -C "$BIN_DIR" gitleaks && rm -f "$BIN_DIR/gitleaks.tgz" \
				|| warn "gitleaks: fetch failed; see https://github.com/gitleaks/gitleaks/releases" ;;
		osv-scanner)
			fetch "https://github.com/google/osv-scanner/releases/download/v1.9.1/osv-scanner_${OS}_${GOARCH}" "$BIN_DIR/osv-scanner" \
				|| warn "osv-scanner: fetch failed; see https://github.com/google/osv-scanner/releases" ;;
		trivy)
			fetch "https://github.com/aquasecurity/trivy/releases/download/v0.56.2/trivy_0.56.2_${OS}-${GOARCH}.tar.gz" "$BIN_DIR/trivy.tgz" \
				&& tar -xzf "$BIN_DIR/trivy.tgz" -C "$BIN_DIR" trivy && rm -f "$BIN_DIR/trivy.tgz" \
				|| warn "trivy: fetch failed; see https://github.com/aquasecurity/trivy/releases" ;;
		dependency-check)
			ver="11.1.0"
			fetch "https://github.com/jeremylong/DependencyCheck/releases/download/v${ver}/dependency-check-${ver}-release.zip" "$BIN_DIR/dc.zip" \
				&& unzip -oq "$BIN_DIR/dc.zip" -d "$BIN_DIR" && rm -f "$BIN_DIR/dc.zip" \
				&& ln -sf "$BIN_DIR/dependency-check/bin/dependency-check.sh" "$BIN_DIR/dependency-check" \
				|| warn "dependency-check: fetch failed (needs Java); see https://owasp.org/www-project-dependency-check/" ;;
		*) warn "unknown tool: $t" ;;
	esac
}

for t in $TOOLS; do install_one "$t"; done
echo
report
log "done. Re-run with --check anytime; the backend also reports availability at GET /api/android/environment."
