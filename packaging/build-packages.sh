#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  KB-Desk  ·  packaging/build-packages.sh
#
#  Builds distributable packages of KB-Desk:
#     * .deb   (Debian/Ubuntu)      — via dpkg-deb
#     * .rpm   (Fedora/RHEL/openSUSE) — via rpmbuild, if installed
#     * .tar.gz (any Linux)          — portable, includes install.sh
#
#  Usage:
#     ./packaging/build-packages.sh            # build + package
#     ./packaging/build-packages.sh --no-build # package existing release binaries
#
#  Output: dist/
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NO_BUILD=0
[ "${1:-}" = "--no-build" ] && NO_BUILD=1

VERSION="$(grep -m1 -E '^version' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
[ -n "$VERSION" ] || { echo "could not read version"; exit 1; }

if command -v dpkg >/dev/null 2>&1; then
    ARCH="$(dpkg --print-architecture)"
else
    case "$(uname -m)" in
        x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; *) ARCH="$(uname -m)" ;;
    esac
fi

DIST="$ROOT/dist"
BUILD="$ROOT/packaging/.build"
BINS=(kbdesk kbdesk-server kbdesk-host kbdesk-client kbdesk-web)
OUT="$ROOT/target/release"

echo "KB-Desk packaging"
echo "  version : $VERSION"
echo "  arch    : $ARCH"
echo "  output  : $DIST"

# ── 1. build ────────────────────────────────────────────────────────────────
if [ "$NO_BUILD" = "1" ]; then
    echo "==> skipping build (--no-build)"
else
    echo "==> cargo build --release"
    cargo build --release
fi

for b in "${BINS[@]}"; do
    [ -x "$OUT/$b" ] || { echo "missing release binary: $OUT/$b"; exit 1; }
done

rm -rf "$BUILD" "$DIST"
mkdir -p "$BUILD" "$DIST"

# ── 2. assemble a common install tree ───────────────────────────────────────
# This tree is reused by every package format.
stage_common() {
    local dest="$1"
    mkdir -p \
        "$dest/usr/bin" \
        "$dest/usr/share/applications" \
        "$dest/usr/share/icons/hicolor/scalable/apps" \
        "$dest/usr/lib/systemd/system" \
        "$dest/usr/lib/systemd/user" \
        "$dest/etc/kbdesk" \
        "$dest/usr/share/doc/kbdesk"

    for b in "${BINS[@]}"; do
        install -m 0755 "$OUT/$b" "$dest/usr/bin/$b"
    done

    install -m 0644 "$ROOT/packaging/kbdesk-client.desktop" \
        "$dest/usr/share/applications/kbdesk-client.desktop"
    install -m 0644 "$ROOT/packaging/kbdesk.svg" \
        "$dest/usr/share/icons/hicolor/scalable/apps/kbdesk.svg"
    install -m 0644 "$ROOT/packaging/systemd/kbdesk-server.service" \
        "$dest/usr/lib/systemd/system/kbdesk-server.service"
    install -m 0644 "$ROOT/packaging/systemd/kbdesk-web.service" \
        "$dest/usr/lib/systemd/system/kbdesk-web.service"
    install -m 0644 "$ROOT/packaging/systemd/kbdesk-host.service" \
        "$dest/usr/lib/systemd/user/kbdesk-host.service"
    install -m 0644 "$ROOT/packaging/kbdesk-web.env" \
        "$dest/etc/kbdesk/kbdesk-web.env"
    install -m 0644 "$ROOT/packaging/kbdesk-server.env" \
        "$dest/etc/kbdesk/kbdesk-server.env"
    install -m 0644 "$ROOT/packaging/kbdesk-host.env" \
        "$dest/etc/kbdesk/kbdesk-host.env"
    install -m 0644 "$ROOT/README.md" "$dest/usr/share/doc/kbdesk/README.md"
    install -m 0644 "$ROOT/LICENSE" "$dest/usr/share/doc/kbdesk/LICENSE"
}

# ── 3. .deb ─────────────────────────────────────────────────────────────────
build_deb() {
    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "==> dpkg-deb not found; skipping .deb"
        return
    fi
    local stage="$BUILD/kbdesk_${VERSION}_${ARCH}"
    stage_common "$stage"
    mkdir -p "$stage/DEBIAN"

    cat > "$stage/DEBIAN/control" <<EOF
Package: kbdesk
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: KB-Desk contributors <noreply@example.com>
Depends: libc6 (>= 2.31)
Recommends: libxkbcommon0, libwayland-client0, libx11-6
Description: KB-Desk remote desktop (agent, relay, viewer, web viewer)
 KB-Desk is an original, self-hosted remote desktop tool. It shares a
 screen and injects remote mouse/keyboard input over TCP, either directly
 or through a relay server.
 .
 This package provides:
  * kbdesk-host   - the agent that shares and controls the local screen
  * kbdesk-server - the relay / rendezvous server
  * kbdesk-client - the native viewer (GUI)
  * kbdesk-web    - a browser-based viewer served over HTTP/WebSocket
  * kbdesk        - one-command launcher for the above
EOF

    cat > "$stage/DEBIAN/conffiles" <<EOF
/etc/kbdesk/kbdesk-web.env
/etc/kbdesk/kbdesk-host.env
EOF

    cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
    chmod 0755 "$stage/DEBIAN/postinst"

    cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
    chmod 0755 "$stage/DEBIAN/postrm"

    local out="$DIST/kbdesk_${VERSION}_${ARCH}.deb"
    dpkg-deb --build --root-owner-group "$stage" "$out" >/dev/null
    echo "==> built $out"
}

# ── 4. .rpm ─────────────────────────────────────────────────────────────────
build_rpm() {
    if ! command -v rpmbuild >/dev/null 2>&1; then
        echo "==> rpmbuild not found; skipping .rpm"
        echo "    (install rpm-build to produce .rpm packages)"
        return
    fi
    local stage="$BUILD/rpm-stage"
    stage_common "$stage"
    local top="$BUILD/rpm"
    mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    local files
    files="$(cd "$stage" && find . -type f -o -type l | sed 's|^\.||' | sort)"

    cat > "$top/SPECS/kbdesk.spec" <<EOF
Name:           kbdesk
Version:        $VERSION
Release:        1
Summary:        KB-Desk remote desktop (agent, relay, viewer, web viewer)
License:        MIT
BuildArch:      $ARCH
AutoReqProv:    no

%description
KB-Desk is an original, self-hosted remote desktop tool.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a $stage/. %{buildroot}/

%files
$files

%changelog
EOF

    rpmbuild -bb \
        --define "_topdir $top" \
        --define "_rpmdir $DIST" \
        --define "_binary_payload w2.xzdio" \
        "$top/SPECS/kbdesk.spec" >/dev/null
    # rpmbuild drops into $DIST/<arch>/
    local built
    built="$(find "$DIST" -name 'kbdesk-*.rpm' | head -1)"
    if [ -n "$built" ]; then
        mv "$built" "$DIST/"
        rmdir "$DIST/$ARCH" 2>/dev/null || true
        echo "==> built $DIST/$(basename "$built")"
    fi
}

# ── 5. .tar.gz ──────────────────────────────────────────────────────────────
build_tar() {
    local stage="$BUILD/tar/kbdesk-${VERSION}-linux-${ARCH}"
    mkdir -p "$stage"
    stage_common "$stage"

    cat > "$stage/install.sh" <<'EOF'
#!/usr/bin/env bash
# Install KB-Desk from this tarball into /usr/local (needs sudo).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"

sudo install -d "$PREFIX/bin" \
    "$PREFIX/share/applications" \
    "$PREFIX/share/icons/hicolor/scalable/apps" \
    "/etc/kbdesk"

for b in kbdesk kbdesk-server kbdesk-host kbdesk-client kbdesk-web; do
    sudo install -m 0755 "$HERE/usr/bin/$b" "$PREFIX/bin/$b"
done
sudo install -m 0644 "$HERE/usr/share/applications/kbdesk-client.desktop" \
    "$PREFIX/share/applications/kbdesk-client.desktop"
sudo install -m 0644 "$HERE/usr/share/icons/hicolor/scalable/apps/kbdesk.svg" \
    "$PREFIX/share/icons/hicolor/scalable/apps/kbdesk.svg"
sudo install -m 0644 "$HERE/etc/kbdesk/kbdesk-web.env" /etc/kbdesk/kbdesk-web.env
sudo install -m 0644 "$HERE/etc/kbdesk/kbdesk-host.env" /etc/kbdesk/kbdesk-host.env
echo "installed KB-Desk into $PREFIX/bin"
echo "run:  kbdesk-client   |   kbdesk-server   |   kbdesk-host   |   kbdesk-web"
EOF
    chmod 0755 "$stage/install.sh"

    local out="$DIST/kbdesk-${VERSION}-linux-${ARCH}.tar.gz"
    tar -C "$BUILD/tar" -czf "$out" "kbdesk-${VERSION}-linux-${ARCH}"
    echo "==> built $out"
}

build_deb
build_rpm
build_tar

echo
echo "Done. Artifacts:"
ls -lh "$DIST"
