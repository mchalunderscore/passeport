#!/usr/bin/env bash
#
# Build Passeport.app and package it into a distributable dist/Passeport.dmg.
#
# Default policy: unsigned/local-only distribution. macOS Gatekeeper will show a
# one-time confirmation on first run.
#
# Usage:
#   scripts/make-dmg.sh
#
# Env (opt-in signing/notarization for real distribution):
#   CODESIGN_IDENTITY   "Developer ID Application: …" — signs the bundled
#                       passeport-core helper with the hardened runtime and
#                       re-signs the app. Required before notarization.
#   NOTARIZE=1          submit the signed app for notarization + staple.
#   NOTARY_PROFILE      notarytool keychain profile name (see `xcrun notarytool
#                       store-credentials`). Required when NOTARIZE=1.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIGURATION="${CONFIGURATION:-Release}"
DERIVED_DATA="${DERIVED_DATA:-/tmp/passeport-release-dd}"
APP="$ROOT/dist/Passeport.app"
DMG="$ROOT/dist/Passeport.dmg"
VOLNAME="Passeport"

if [ -z "${DEVELOPER_DIR:-}" ] && [ -d /Applications/Xcode.app/Contents/Developer ]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi

echo "==> Building $CONFIGURATION (unsigned)"
BUILD_ARGS=(
  -project "$ROOT/Passeport.xcodeproj"
  -scheme Passeport
  -configuration "$CONFIGURATION"
  -destination "generic/platform=macOS"
  -derivedDataPath "$DERIVED_DATA"
  "ARCHS=arm64 x86_64"
  ONLY_ACTIVE_ARCH=NO
  CODE_SIGNING_ALLOWED=NO
  CODE_SIGNING_REQUIRED=NO
  CODE_SIGN_IDENTITY=
)
xcodebuild "${BUILD_ARGS[@]}" build

BUILT="$DERIVED_DATA/Build/Products/$CONFIGURATION/Passeport.app"
rm -rf "$APP"
mkdir -p "$ROOT/dist"
ditto "$BUILT" "$APP"
[ -x "$(command -v xattr)" ] && xattr -cr "$APP" || true

[ -f "$ROOT/NOTICE" ] && cp "$ROOT/NOTICE" "$APP/Contents/Resources/NOTICE" || true

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  echo "==> Signing passeport-core with the hardened runtime"
  codesign --force --options runtime --timestamp -s "$CODESIGN_IDENTITY" \
    "$APP/Contents/Helpers/passeport-core"
  echo "==> Signing app with the hardened runtime"
  # The helper was signed inside-out above; sign the app (main executable and
  # bundle seal) without --deep so its signature is kept. Seed storage uses an
  # encrypted file and therefore requires no restricted entitlement.
  codesign --force --options runtime --timestamp -s "$CODESIGN_IDENTITY" "$APP"
  codesign --verify --strict --verbose=2 "$APP"

  if [ "${NOTARIZE:-0}" = "1" ]; then
    : "${NOTARY_PROFILE:?NOTARIZE=1 requires NOTARY_PROFILE}"
    echo "==> Notarizing"
    NOTARY_ZIP="$(mktemp -d)/Passeport.zip"
    ditto -c -k --keepParent "$APP" "$NOTARY_ZIP"
    xcrun notarytool submit "$NOTARY_ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$APP"
  fi
else
  echo "note: CODESIGN_IDENTITY unset — app and bundled tools are UNSIGNED (local-only)"
fi

echo "==> Building DMG"
STAGING="$(mktemp -d)"
ditto "$APP" "$STAGING/Passeport.app"
ln -s /Applications "$STAGING/Applications"
rm -f "$DMG"
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGING" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGING"

echo ""
echo "Built: $DMG"
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  if [ "${NOTARIZE:-0}" = "1" ]; then
    echo "Signed + notarized package complete."
  else
    echo "Signed package complete (not notarized — Gatekeeper may still warn until notarized)."
  fi
else
  echo "Unsigned package complete — users will see a one-time Gatekeeper confirmation on first launch."
fi
