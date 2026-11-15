#!/usr/bin/env bash
# ARTEX cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   ANDROIDLAB_TARGET_OS=linux             One target OS in single-target mode.
#   ANDROIDLAB_TARGET_ARCH=amd64           One target arch in single-target mode.
#   ANDROIDLAB_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   ANDROIDLAB_BUILD_VERSION=v0.3.3        Version embedded in the binary and archive name.
#   ANDROIDLAB_OUTPUT=/path/to/artex       Explicit binary path in single-target mode.
#   ANDROIDLAB_OUTPUT_DIR=dist             Directory for default binary paths.
#   ANDROIDLAB_PACKAGE=1                   Create a zip archive for each target.
#   ANDROIDLAB_PACKAGE_DIR=dist            Directory for release archives.
#   ANDROIDLAB_COMPRESS=off                UPX mode: off, auto, or required.
#   ANDROIDLAB_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   ANDROIDLAB_SKIP_FRONTEND=1             Reuse internal/server/webui/dist (for CI artifact builds).
#   ANDROIDLAB_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   ANDROIDLAB_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./build.sh                         Build for the current OS and architecture
  ./build.sh --target linux/amd64   Build for a specific target
  ./build.sh --release               Build and package all supported targets

Options:
  --release              Build Linux, macOS, and Windows amd64/arm64 targets and create zips
  --target OS/ARCH       Set one target, for example windows/amd64
  --upx                  Require UPX compression (may affect compatibility on some Linux systems)
  --no-compress          Disable UPX; only strip with the Go linker and compress the zip
  --help                 Show this help

Override the multi-target list with ANDROIDLAB_TARGETS, for example:
  ANDROIDLAB_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
ANDROIDLAB_RELEASE="${ANDROIDLAB_RELEASE:-0}"
ANDROIDLAB_COMPRESS="${ANDROIDLAB_COMPRESS:-off}"
ANDROIDLAB_PACKAGE="${ANDROIDLAB_PACKAGE:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      ANDROIDLAB_RELEASE=1
      ANDROIDLAB_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target requires an OS/ARCH argument"
      target_arg="$2"
      case "$target_arg" in
        */*)
          ANDROIDLAB_TARGET_OS="${target_arg%%/*}"
          ANDROIDLAB_TARGET_ARCH="${target_arg##*/}"
          ANDROIDLAB_TARGETS="$target_arg"
          ;;
        *) die "Target must be OS/ARCH, for example linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      ANDROIDLAB_COMPRESS=0
      shift
      ;;
    --upx)
      ANDROIDLAB_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "Unknown option: $1 (use --help for usage)" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "Go 1.26 or newer is required"

ANDROIDLAB_GOSUMDB="${ANDROIDLAB_GOSUMDB:-sum.golang.org}"
if [ -z "${ANDROIDLAB_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    ANDROIDLAB_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    ANDROIDLAB_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed as v0.3.3; keep the binary version consistent.
ANDROIDLAB_BUILD_VERSION="${ANDROIDLAB_BUILD_VERSION#v}"
ANDROIDLAB_OUTPUT_DIR="${ANDROIDLAB_OUTPUT_DIR:-dist}"
ANDROIDLAB_PACKAGE_DIR="${ANDROIDLAB_PACKAGE_DIR:-$ANDROIDLAB_OUTPUT_DIR}"
ANDROIDLAB_UPX_ARGS="${ANDROIDLAB_UPX_ARGS:---best --lzma}"

if [ "${ANDROIDLAB_RELEASE}" = "1" ]; then
  ANDROIDLAB_TARGETS="${ANDROIDLAB_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  ANDROIDLAB_TARGET_OS="${ANDROIDLAB_TARGET_OS:-$(GOSUMDB="$ANDROIDLAB_GOSUMDB" go env GOOS)}"
  ANDROIDLAB_TARGET_ARCH="${ANDROIDLAB_TARGET_ARCH:-$(GOSUMDB="$ANDROIDLAB_GOSUMDB" go env GOARCH)}"
  ANDROIDLAB_TARGETS="${ANDROIDLAB_TARGETS:-${ANDROIDLAB_TARGET_OS}/${ANDROIDLAB_TARGET_ARCH}}"
fi

if [ "${ANDROIDLAB_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d internal/server/webui/dist ] || die "ANDROIDLAB_SKIP_FRONTEND=1 but internal/server/webui/dist does not exist"
else
  command -v npm >/dev/null 2>&1 || die "npm was not found (Node.js/npm is required to build the frontend)"
  command -v rsync >/dev/null 2>&1 || die "rsync was not found"
  info "Building frontend static assets"
  if [ "${ANDROIDLAB_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "Copying frontend assets to internal/server/webui/dist"
  mkdir -p internal/server/webui/dist
  rsync -a --delete web/out/ internal/server/webui/dist/
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$ANDROIDLAB_COMPRESS" in
    0|off|false|none)
      info "Skipping UPX: $binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "ANDROIDLAB_COMPRESS must be off, auto, or required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$ANDROIDLAB_COMPRESS" = "required" ]; then
      die "ANDROIDLAB_COMPRESS=required but UPX was not found"
    fi
    warn "UPX was not found; keeping the linker-compressed binary: $binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$ANDROIDLAB_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$ANDROIDLAB_COMPRESS" = "required" ]; then
      die "UPX compression failed: $binary"
    fi
    warn "UPX does not support this target format; keeping the uncompressed binary: $binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX compression complete: $binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="artex-${ANDROIDLAB_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${ANDROIDLAB_PACKAGE_DIR}/${package_name}"
  archive="${ANDROIDLAB_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "zip is required for packaging"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  # The supervising start script is the official entry point: one-click update in the UI relies on it to relaunch the process after exit;
  # running the artex binary directly means it never comes back after an update. Only the script for the target OS is bundled.
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$ANDROIDLAB_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  ok "Release archive: $archive"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "Invalid target: $target (must be OS/ARCH)" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "Unsupported OS: $goos (supported: linux, darwin, windows)" ;;
  esac

  binary_name="artex"
  [ "$goos" = "windows" ] && binary_name="artex.exe"
  if [ -n "${ANDROIDLAB_OUTPUT:-}" ] && [ "$ANDROIDLAB_RELEASE" != "1" ]; then
    output="$ANDROIDLAB_OUTPUT"
  else
    output="${ANDROIDLAB_OUTPUT_DIR}/artex-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "Building ${goos}/${goarch}, version ${ANDROIDLAB_BUILD_VERSION}"
  GOSUMDB="$ANDROIDLAB_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${ANDROIDLAB_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/artex

  compress_binary "$output" "$goos"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  if [ "$ANDROIDLAB_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  ok "Build complete: $output"
}

write_checksums() {
  [ "$ANDROIDLAB_PACKAGE" = "1" ] || return 0
  checksum_file="$ANDROIDLAB_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$ANDROIDLAB_PACKAGE_DIR" && for archive in *.zip; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$ANDROIDLAB_PACKAGE_DIR" && for archive in *.zip; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    warn "sha256sum and shasum were not found; skipping SHA256SUMS"
    return 0
  fi
  ok "Checksums: $checksum_file"
}

mkdir -p "$ANDROIDLAB_OUTPUT_DIR"
if [ "$ANDROIDLAB_PACKAGE" = "1" ]; then mkdir -p "$ANDROIDLAB_PACKAGE_DIR"; fi

old_ifs="$IFS"
IFS=','
read -r -a targets <<< "$ANDROIDLAB_TARGETS"
IFS="$old_ifs"
[ "${#targets[@]}" -gt 0 ] || die "ANDROIDLAB_TARGETS cannot be empty"
for target in "${targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  build_target "$target"
done

if [ "$ANDROIDLAB_PACKAGE" = "1" ]; then
  write_checksums
  info "Release packages created in: $ANDROIDLAB_PACKAGE_DIR"
fi
