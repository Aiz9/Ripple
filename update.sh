#!/usr/bin/env bash
# ARTEX update script: (1) Docker update (pull the new image and recreate)  (2) local build update (rebuild the binary)
# Counterpart of install.sh: install handles the first deployment, update upgrades to a new version.
# No manual DB migration is needed -- artex idempotently reruns schema.sql on every startup (including ADD COLUMN/CREATE
# INDEX IF NOT EXISTS), so "restart = migrate". Data (the pgdata volume, ./data, ./skills) is not affected.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# -- Optional: sync the repository to the latest code (compose files, scripts and local build sources all update through it) --
sync_repo(){
  [ -d .git ] && command -v git >/dev/null 2>&1 || { warn "Not a Git working copy; skipping git pull"; return; }
  [ "$(ask 'Pull latest code (git pull --ff-only)? (y/n)' y)" = y ] || return
  if ! git pull --ff-only; then
    warn "git pull could not fast-forward (local changes or diverged branches); resolve it manually and try again"
  fi
}

# -- (1) Docker update --------------------------------
update_docker(){
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "Docker or Docker Compose was not found; run ./install.sh first"
  [ -f .env ] || die ".env was not found; run ./install.sh for the initial deployment"

  # Optional: upgrade to a specific version tag (empty keeps ANDROIDLAB_TAG from .env, default latest)
  local tag; tag="$(ask 'Target image tag (press Enter to keep .env / latest)' '')"
  if [ -n "$tag" ]; then
    if grep -q '^ANDROIDLAB_TAG=' .env; then
      sed -i.bak "s|^ANDROIDLAB_TAG=.*|ANDROIDLAB_TAG=${tag}|" .env && rm -f .env.bak
    else
      printf '\nANDROIDLAB_TAG=%s\n' "$tag" >> .env
    fi
    ok "ANDROIDLAB_TAG set to ${tag}"
  fi

  # Only touch artex: postgres is pinned to 16-alpine and need not be upgraded with it (pulling it wastes bandwidth,
  # and a major version change carries compatibility risk). artex declares depends_on postgres, so running up with the service name
  # starts pg automatically if it is not running, and leaves an already-running one as it is without recreating it.
  info "Pulling the new image (artex only)…"
  docker compose pull artex
  info "Rebuilding and starting (schema migration runs on restart)…"
  docker compose up -d artex
  ok "Update complete → http://localhost:8787"
  info "View logs with: docker compose logs -f artex"
  info "Optional cleanup: docker image prune -f"
}

# -- (2) Local build update ---------------------------
update_local(){
  command -v go >/dev/null 2>&1 || die "Go (>=1.26) was not found: https://go.dev/dl/"
  [ -f config.json ] || warn "config.json was not found; use ./install.sh for the initial deployment"
  ok "Go: $(go version)"

  if command -v npm >/dev/null 2>&1; then
    info "Rebuilding the frontend static output…"
    ( cd web && npm ci && npm run build:static )
    rm -rf internal/server/webui/dist && cp -r web/out internal/server/webui/dist
    info "Rebuilding the self-contained binary…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "npm was not found: building the backend without an embedded frontend (run npm run dev separately)"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "Build complete → ./artex"
  warn "Restart the running artex process to apply the update (schema migration runs on restart)"
}

echo "=============================="
echo "  ARTEX updater"
echo "  1) Docker update (pull and rebuild)"
echo "  2) Local update (rebuild with Go)"
echo "=============================="
case "$(ask 'Select' 1)" in
  1) sync_repo; update_docker ;;
  2) sync_repo; update_local ;;
  *) die "Invalid selection" ;;
esac
