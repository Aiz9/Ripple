#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -d web/node_modules ]]; then
  (cd web && npm ci)
fi
(cd web && npm run build:static)
mkdir -p internal/server/webui/dist
cp -a web/out/. internal/server/webui/dist/
CGO_ENABLED=0 go build -tags embedui -trimpath -o androidlab ./cmd/artex
echo "Built Ripple. Run ./start.sh after configuring its database."
