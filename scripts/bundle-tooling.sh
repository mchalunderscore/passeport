#!/usr/bin/env bash
#
# Vendor the permissive age CLI into Passeport.app/Contents/Helpers:
#
#   rage      (str4d/rage, MIT OR Apache-2.0) — age encryption, pure Rust
#   rage-keygen
#
# plus a name-symlink so users can call either name:  age -> rage.
#
# gpg and minisign are Passeport's OWN pure-Rust CLIs (passeport-core, already
# bundled) — no third-party gpg / minisign / rsign2 is shipped. gpg has no
# permissive drop-in (the chameleon is GPL + needs a GNU agent), and we already
# implement the full minisign format (sign + verify), so bundling rsign2 would be
# redundant.
#
# Usage:
#   scripts/bundle-tooling.sh [path/to/Passeport.app]
#
# Env:
#   CODESIGN_IDENTITY   if set, each bundled Mach-O is signed with the hardened
#                       runtime (required before notarization).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="${1:-$ROOT/dist/Passeport.app}"
HELPERS="$APP/Contents/Helpers"

if [ ! -d "$APP" ]; then
  echo "error: app bundle not found at $APP (build it first)" >&2
  exit 1
fi
command -v cargo >/dev/null || { echo "error: cargo (Rust toolchain) required" >&2; exit 1; }
mkdir -p "$HELPERS"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  arm64) HOST_TARGET="aarch64-apple-darwin" ;;
  x86_64) HOST_TARGET="x86_64-apple-darwin" ;;
  *) echo "error: unsupported host arch $HOST_ARCH" >&2; exit 1 ;;
esac
OTHER_TARGET="$([ "$HOST_TARGET" = aarch64-apple-darwin ] && echo x86_64-apple-darwin || echo aarch64-apple-darwin)"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Build rage for the host target (and the other, if its std is installed) so we
# can ship a universal binary.
build_target() {
  local target="$1"
  echo "==> building rage for $target"
  cargo install --quiet --force --locked --root "$STAGE/$target" --target "$target" rage
}

build_target "$HOST_TARGET"
HAVE_OTHER=0
if rustup target list --installed 2>/dev/null | grep -qx "$OTHER_TARGET"; then
  if build_target "$OTHER_TARGET"; then HAVE_OTHER=1; fi
else
  echo "note: $OTHER_TARGET std not installed (rustup target add $OTHER_TARGET) — shipping single-arch $HOST_ARCH"
fi

# Assemble each binary as a universal Mach-O (or single-arch if the other target
# is unavailable) into Contents/Helpers.
install_bin() {
  local name="$1"
  local host="$STAGE/$HOST_TARGET/bin/$name"
  [ -x "$host" ] || { echo "error: $name not produced for $HOST_TARGET" >&2; exit 1; }
  if [ "$HAVE_OTHER" = 1 ] && [ -x "$STAGE/$OTHER_TARGET/bin/$name" ]; then
    lipo -create -o "$HELPERS/$name" "$host" "$STAGE/$OTHER_TARGET/bin/$name"
  else
    cp -f "$host" "$HELPERS/$name"
  fi
  chmod 755 "$HELPERS/$name"
}

install_bin rage
install_bin rage-keygen

# Name-symlink (relative, so it survives the bundle being moved/copied).
( cd "$HELPERS" && ln -sf rage age )
echo "==> symlinked age -> rage"

# Reproduce the bundled crates' license texts (MIT/Apache require the full text
# and copyright notice when redistributing binaries — NOTICE only summarizes).
LICDIR="$APP/Contents/Resources/licenses"
mkdir -p "$LICDIR"
REG="$HOME/.cargo/registry/src"
if [ -d "$REG" ]; then
  for crate in rage age; do
    src="$(find "$REG" -maxdepth 2 -type d -name "$crate-*" 2>/dev/null | sort -V | tail -1)"
    [ -n "$src" ] || continue
    for lic in "$src"/LICENSE* "$src"/COPYING* "$src"/UNLICENSE*; do
      [ -f "$lic" ] && cp -f "$lic" "$LICDIR/${crate}-$(basename "$lic")"
    done
  done
  echo "==> copied bundled-crate license texts into $LICDIR"
else
  echo "note: cargo registry not found — license texts not copied (add them manually for redistribution)"
fi

# Sign every Mach-O with the hardened runtime (symlinks are not signed).
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  for bin in passeport-core rage rage-keygen; do
    [ -f "$HELPERS/$bin" ] || continue
    echo "==> codesign $bin"
    codesign --force --options runtime --timestamp -s "$CODESIGN_IDENTITY" "$HELPERS/$bin"
  done
else
  echo "note: CODESIGN_IDENTITY unset — bundled binaries are UNSIGNED (set it before notarizing)"
fi

echo ""
echo "Bundled into $HELPERS:"
ls -l "$HELPERS"
