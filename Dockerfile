# syntax=docker/dockerfile:1
#
# Multi-stage build: static web export -> single Go binary (web UI embedded) -> runtime image.
# The original Docker Hub image (autumn27/artex) is gone, so this repository builds entirely from source:
#   docker compose build        # or: docker build -t artex:local .
# TARGETARCH is injected by buildx (amd64/arm64); Go cross-compiles without QEMU.
# The runtime layer only installs tools; all compilation happens in the build stages.
# Module/package mirrors can be overridden (the defaults favor networks in mainland China):
#   --build-arg GOPROXY=https://goproxy.cn,direct
#   --build-arg NPM_REGISTRY=https://registry.npmmirror.com
# Releases use --build-arg ANDROIDLAB_BINARY_SOURCE=prebuilt to reuse the verified release binary;
# by default the image still builds from source and downloads no prebuilt ARTEX artifacts.
ARG ANDROIDLAB_BINARY_SOURCE=source

########## Stage 1: static web export ##########
FROM --platform=$BUILDPLATFORM node:22-bookworm AS web
ARG NPM_REGISTRY=https://registry.npmmirror.com
WORKDIR /web
# --ignore-scripts skips prepare (husky): there is no .git in the container, so husky would fail.
# Next.js/Biome platform binaries come through optionalDependencies and need no lifecycle scripts.
COPY web/package.json web/package-lock.json ./
RUN npm config set registry "$NPM_REGISTRY" && npm ci --ignore-scripts
COPY web/ ./
RUN NEXT_EXPORT=1 npm run build:static

########## Stage 2: Go backend (web UI embedded, static build) ##########
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS gobuild
ARG TARGETOS
ARG TARGETARCH
ARG ANDROIDLAB_BUILD_VERSION=dev
ARG GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
# This repository uses the local norma module through a replace directive; its module files must exist before downloading dependencies.
COPY third_party/norma/go.mod third_party/norma/go.sum ./third_party/norma/
RUN go mod download
COPY . .
# Static web output is copied from the web stage (.dockerignore excludes the host's dist, so there is no conflict).
COPY --from=web /web/out/ internal/server/webui/dist/
RUN version="${ANDROIDLAB_BUILD_VERSION#v}" \
    && CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build \
       -tags embedui -trimpath -ldflags "-s -w -X main.version=${version}" \
       -o /out/artex ./cmd/artex

FROM scratch AS source
COPY --from=gobuild /out/artex /out/artex

########## Optional release input: reuse the verified binary without recompiling ##########
FROM scratch AS prebuilt
ARG TARGETARCH
COPY dist/${TARGETARCH}/artex /out/artex

FROM ${ANDROIDLAB_BINARY_SOURCE} AS binary

########## Stage 3: runtime image (tools + Playwright preinstalled) ##########
FROM python:3.12-slim-bookworm AS runtime
ARG NPM_REGISTRY=https://registry.npmmirror.com
# Pinned to the exact MCP/CLI dependencies below, so the tools never look for another, uninstalled Chromium version.
ARG PLAYWRIGHT_VERSION=1.64.0-alpha-1790635538000
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG PLAYWRIGHT_CLI_VERSION=0.1.22
ARG PLAYWRIGHT_DOWNLOAD_HOST
# The npm registry can be overridden; browsers come from the official CDN by default, or a mirror via build arg.
ENV npm_config_registry=$NPM_REGISTRY \
    PLAYWRIGHT_DOWNLOAD_HOST=$PLAYWRIGHT_DOWNLOAD_HOST
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add or remove as needed).
# Node and the web build both use 22.x instead of the end-of-life 20.x.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip adb apktool apksigner default-jre-headless \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Preinstall Playwright MCP and CLI globally, so nothing is downloaded with npx at runtime.
# @playwright/mcp: the browser MCP runs `npx @playwright/mcp` directly (installed globally, no -y/@latest needed).
# @playwright/cli: provides playwright-cli; --help after install verifies that it runs.
# Then install playwright (browser management) and use --with-deps to preinstall chromium and its system dependencies,
# so MCP/CLI work on first start inside the container without downloading a browser.
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" \
      "@playwright/cli@${PLAYWRIGHT_CLI_VERSION}" "playwright@${PLAYWRIGHT_VERSION}" \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && node -e 'const fs = require("node:fs"), cp = require("node:child_process"); const root = cp.execFileSync("npm", ["root", "-g"], {encoding:"utf8"}).trim(); fs.symlinkSync(require(root + "/playwright").chromium.executablePath(), "/usr/local/bin/artex-chromium");' \
    && rm -rf /var/lib/apt/lists/*
# MCP/CLI use the Chromium installed in the container by default: no Chrome, display server or runtime download needed.
# The container runs as root, so Chromium's process sandbox is unavailable; override this in a custom non-root deployment.
ENV PLAYWRIGHT_MCP_EXECUTABLE_PATH=/usr/local/bin/artex-chromium \
    PLAYWRIGHT_MCP_HEADLESS=true \
    PLAYWRIGHT_MCP_SANDBOX=false
WORKDIR /app
# The built-in browser MCP uses npx @playwright/mcp. npm exec does not guarantee resolving global packages,
# so the preinstalled dependencies are exposed on the app's local dependency path and subdirectories can start the same version offline.
RUN ln -s "$(npm root -g)" /app/node_modules \
    && npx --offline --no-install @playwright/mcp --help > /dev/null
# Single binary produced by the build stage (web UI embedded)
COPY --from=binary /out/artex /app/artex
# Run directly so container stop reaches Go's graceful shutdown handler.
RUN chmod +x /app/artex
COPY skills/ /app/skills/
# data/ (SQLite + jwt.key) persistence point
VOLUME ["/app/data"]
EXPOSE 8797 8798
ENTRYPOINT ["/app/artex"]
CMD ["-addr", ":8797", "-proxy", ":8798"]
