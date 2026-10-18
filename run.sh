#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  KB-Desk  ·  run.sh   (Linux / macOS)
#
#  One command to build (first time only) and start KB-Desk.
#
#     ./run.sh              # relay + host + web viewer  (viewers need only an ID)
#     ./run.sh web          # host + web viewer, no relay
#     ./run.sh serve        # relay + web viewer (server: control hosts from any browser)
#     ./run.sh host         # share this screen (direct)
#     ./run.sh relay        # run the relay server only
#     ./run.sh viewer       # native desktop viewer
#
#  Any options pass through to the launcher, e.g.
#     ./run.sh up --password secret --web-port 8080
#     ./run.sh web --web-port 9000
#
#  Force a rebuild with:  KB_DESK_REBUILD=1 ./run.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "KB-Desk needs Rust to build. Install it from https://rustup.rs and re-run." >&2
    exit 1
fi

BIN="$ROOT/target/release/kbdesk"
if [ ! -x "$BIN" ] || [ -n "${KB_DESK_REBUILD:-}" ]; then
    echo "Building KB-Desk (first run only; this can take a few minutes)…"
    cargo build --release
fi

exec "$BIN" "$@"
