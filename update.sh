#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  KB-Desk  ·  update.sh
#
#  Rebuild KB-Desk after code changes.
#
#  Usage:
#     ./update.sh                 # rebuild (release) once
#     ./update.sh --debug         # rebuild (debug, faster) once
#     ./update.sh --test          # rebuild, then run the test suite
#     ./update.sh --watch         # rebuild automatically on every change
#     ./update.sh --watch --debug # watch + fast debug builds
#     ./update.sh --clean         # cargo clean, then rebuild
#     ./update.sh --run server    # rebuild then launch a binary
#                                 #   (server | host | client | web)
#     ./update.sh --package       # rebuild, then build .deb/.tar.gz in dist/
#
#  Exit codes: 0 success, 1 build failure (in one-shot mode).
#  In --watch mode the script keeps running through build failures.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

MODE="release"      # release | debug
WATCH=0
RUN_TESTS=0
CLEAN=0
PACKAGE=0
RUN_BIN=""

if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""
fi

usage() { sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --watch|-w)  WATCH=1 ;;
        --debug|-d)  MODE="debug" ;;
        --release|-r) MODE="release" ;;
        --test|-t)   RUN_TESTS=1 ;;
        --clean)     CLEAN=1 ;;
        --package|-p) PACKAGE=1 ;;
        --run)       shift; RUN_BIN="${1:-}" ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "${C_RED}unknown option: $1${C_RST}"; usage; exit 2 ;;
    esac
    shift
done

if [ "$MODE" = "release" ]; then
    PROFILE_ARGS=("--release")
    OUT_DIR="target/release"
else
    PROFILE_ARGS=()
    OUT_DIR="target/debug"
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "${C_RED}cargo not found on PATH. Install Rust: https://rustup.rs${C_RST}"
    exit 1
fi

# Content fingerprint of everything that can affect a build.
fingerprint() {
    find "$ROOT" \
        -type f \
        \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) \
        -not -path "*/target/*" \
        -print0 2>/dev/null \
        | sort -z \
        | xargs -0 cksum 2>/dev/null \
        | cksum
}

stamp() { date +'%H:%M:%S'; }

do_build() {
    echo "${C_BLU}==> [$(stamp)] building KB-Desk ($MODE)${C_RST}"

    if [ "$CLEAN" = "1" ]; then
        echo "${C_YEL}    cargo clean${C_RST}"
        cargo clean
        CLEAN=0
    fi

    local start
    start=$(date +%s)
    if cargo build "${PROFILE_ARGS[@]}"; then
        local elapsed=$(( $(date +%s) - start ))
        echo "${C_GRN}==> build OK in ${elapsed}s${C_RST}"
        echo "    binaries in ${OUT_DIR}/:"
        for b in kbdesk-server kbdesk-host kbdesk-client kbdesk-web; do
            if [ -x "$OUT_DIR/$b" ]; then
                printf '      %s%-18s%s %s\n' "$C_DIM" "$b" "$C_RST" \
                    "$(du -h "$OUT_DIR/$b" 2>/dev/null | cut -f1)"
            fi
        done
        if [ "$RUN_TESTS" = "1" ]; then
            echo "${C_BLU}==> running tests${C_RST}"
            if cargo test "${PROFILE_ARGS[@]}"; then
                echo "${C_GRN}==> tests passed${C_RST}"
            else
                echo "${C_RED}==> tests FAILED${C_RST}"
                return 1
            fi
        fi
        return 0
    else
        echo "${C_RED}==> build FAILED${C_RST}"
        return 1
    fi
}

maybe_run() {
    [ -z "$RUN_BIN" ] && return 0
    local path="$OUT_DIR/kbdesk-$RUN_BIN"
    if [ ! -x "$path" ]; then
        echo "${C_RED}no such binary: $path${C_RST} (try: server, host, client)"
        return 1
    fi
    echo "${C_BLU}==> launching $path${C_RST}"
    exec "$path"
}

# ── one-shot ────────────────────────────────────────────────────────────────
if [ "$WATCH" != "1" ]; then
    if do_build; then
        if [ "$PACKAGE" = "1" ]; then
            echo "${C_BLU}==> building packages${C_RST}"
            "$ROOT/packaging/build-packages.sh" --no-build
        fi
        maybe_run
    else
        exit 1
    fi
    exit 0
fi

# ── watch mode ──────────────────────────────────────────────────────────────
echo "${C_YEL}KB-Desk watcher running${C_RST} — watching *.rs / Cargo.toml for changes."
echo "${C_DIM}Press Ctrl-C to stop.${C_RST}"
trap 'echo; echo "${C_YEL}watcher stopped${C_RST}"; exit 0' INT

last=""
while true; do
    current="$(fingerprint)"
    if [ "$current" != "$last" ]; then
        last="$current"
        echo "${C_DIM}--- change detected at $(stamp) ---${C_RST}"
        # Keep watching even if the build fails, so you can fix and save again.
        do_build || true
        echo "${C_DIM}watching for further changes…${C_RST}"
    fi
    sleep 1
done
