#!/usr/bin/env bash
#
# Build Passeport.app and package it into a distributable dist/Passeport.dmg.
#
# Current policy: always unsigned/local-only distribution.
#
# Usage:
#   scripts/make-dmg.sh
#
# This intentionally skips code signing and notarization.
# macOS Gatekeeper will show a one-time confirmation on first run.
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
  -derivedDataPath "$DERIVED_DATA"
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

echo "==> Building DMG"
STAGING="$(mktemp -d)"
ditto "$APP" "$STAGING/Passeport.app"
ln -s /Applications "$STAGING/Applications"
rm -f "$DMG"
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGING" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGING"

echo ""
echo "Built: $DMG"
echo "Unsigned package complete — users will see a one-time Gatekeeper confirmation on first launch."
