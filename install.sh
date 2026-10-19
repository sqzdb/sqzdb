#!/bin/sh
# Install the sqzdb command from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/sqzdb/sqzdb/main/install.sh | sh
#
# Environment:
#   SQZDB_VERSION      a release tag such as v0.1.0 (default: the latest release)
#   SQZDB_INSTALL_DIR  where to put the binary (default: /usr/local/bin as root, else ~/.local/bin)
#   SQZDB_BASE_URL     release download base (default: https://github.com/sqzdb/sqzdb/releases)
#   SQZDB_LIBC         Linux only: gnu (glibc >= 2.17, the fast default) or musl (static; chosen automatically on Alpine)
# Arguments:
#   --uninstall           remove the installed binary
set -eu

REPO_URL="${SQZDB_BASE_URL:-https://github.com/sqzdb/sqzdb/releases}"
VERSION="${SQZDB_VERSION:-${SQWEEZDB_VERSION:-latest}}"   # (SQWEEZDB_*: the names before the rename)
if [ "$(id -u)" = "0" ]; then DEFAULT_DIR="/usr/local/bin"; else DEFAULT_DIR="${HOME}/.local/bin"; fi
INSTALL_DIR="${SQZDB_INSTALL_DIR:-${SQWEEZDB_INSTALL_DIR:-$DEFAULT_DIR}}"

say() { printf 'sqzdb: %s\n' "$*"; }
die() { printf 'sqzdb: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "this installer needs '$1'"; }

if [ "${1:-}" = "--uninstall" ]; then
  if [ -e "$INSTALL_DIR/sqzdb" ]; then rm -f "$INSTALL_DIR/sqzdb"; say "removed $INSTALL_DIR/sqzdb"; else say "nothing installed at $INSTALL_DIR/sqzdb"; fi
  exit 0
fi

os="$(uname -s)"; arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *) die "no prebuilt binary for $arch; build from source: https://github.com/sqzdb/sqzdb#building-from-source" ;;
esac
case "$os" in
  Linux)
    libc="${SQZDB_LIBC:-${SQWEEZDB_LIBC:-}}"
    if [ -z "$libc" ]; then
      libc="gnu"
      if ls /lib/ld-musl-* >/dev/null 2>&1 || { ldd --version 2>&1 | grep -qi musl; }; then libc="musl"; fi
    fi
    case "$libc" in gnu|musl) ;; *) die "SQZDB_LIBC must be gnu or musl" ;; esac
    target="${arch}-unknown-linux-${libc}" ;;
  Darwin) target="${arch}-apple-darwin" ;;
  *) die "no prebuilt binary for $os; build from source: https://github.com/sqzdb/sqzdb#building-from-source" ;;
esac

if command -v curl >/dev/null 2>&1; then fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then fetch() { wget -q -O "$2" "$1"; }
else die "this installer needs curl or wget"; fi
if command -v sha256sum >/dev/null 2>&1; then sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else die "this installer needs sha256sum or shasum to verify the download"; fi
need tar; need mktemp

asset="sqzdb-${target}.tar.gz"
if [ "$VERSION" = "latest" ]; then base="${REPO_URL}/latest/download"; else base="${REPO_URL}/download/${VERSION}"; fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT INT TERM
say "downloading ${asset} (${VERSION})"
fetch "${base}/${asset}" "$tmp/$asset" || die "download failed: ${base}/${asset}"
fetch "${base}/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: ${base}/SHA256SUMS"
want="$(grep " ${asset}\$" "$tmp/SHA256SUMS" | cut -d' ' -f1 | head -n 1)"
[ -n "$want" ] || die "SHA256SUMS has no entry for ${asset}"
got="$(sha256 "$tmp/$asset")"
[ "$want" = "$got" ] || die "checksum mismatch for ${asset}: expected ${want}, got ${got}"

tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/sqzdb-${target}/sqzdb" ] || die "the archive does not contain sqzdb-${target}/sqzdb"
mkdir -p "$INSTALL_DIR" || die "cannot create $INSTALL_DIR (try SQZDB_INSTALL_DIR=... or run as root)"
cp "$tmp/sqzdb-${target}/sqzdb" "$tmp/sqzdb.new" && chmod 0755 "$tmp/sqzdb.new"
mv -f "$tmp/sqzdb.new" "$INSTALL_DIR/sqzdb" 2>/dev/null || cp -f "$tmp/sqzdb.new" "$INSTALL_DIR/sqzdb" || die "cannot write $INSTALL_DIR/sqzdb"
say "installed $("$INSTALL_DIR/sqzdb" version 2>/dev/null || echo sqzdb) to $INSTALL_DIR/sqzdb"
case ":${PATH}:" in *":${INSTALL_DIR}:"*) ;; *) say "add ${INSTALL_DIR} to your PATH, e.g.: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;; esac
# sqweezdb is now sqzdb: an old command next to the new one is left for you to remove
if [ -f "$INSTALL_DIR/sqweezdb" ]; then say "sqweezdb is now called sqzdb; remove the old command with: rm $INSTALL_DIR/sqweezdb"; fi
