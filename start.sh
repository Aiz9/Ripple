#!/bin/sh
# The single launcher for Ripple/ARTEX. Runs only for the lifetime of this
# foreground process (Ctrl-C to stop).
#
#   ./start.sh             start one instance (UI + API on :8797)
#   ./start.sh --dev       dev mode (backend + hot-reload web on :3001)
#   ./start.sh --compose   run the stack via docker compose
#
# Any extra flags pass through unchanged.
cd "$(dirname "$0")" || exit 1
# Enable the web-task agent model (the "Current tasks" pipeline and New APK task)
# in addition to the policy-enforced Assessments dispatcher. These are the
# inherited shell-capable agents, off by default; this deployment opts in.
# Override with ANDROIDLAB_ENABLE_LEGACY_AGENTS=0 ./start.sh to turn it back off.
: "${ANDROIDLAB_ENABLE_LEGACY_AGENTS:=1}"
export ANDROIDLAB_ENABLE_LEGACY_AGENTS
# Source checkout: the Python session manager builds/starts the backend, the
# PostgreSQL container and adb. Packaged releases ship the executable instead.
if [ -f scripts/session.py ]; then
    exec python3 scripts/session.py "$@"
fi
exec ./artex "$@"
