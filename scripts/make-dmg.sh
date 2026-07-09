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
#   CODESIGN_IDENTITY   "Developer ID Application: …" — signs the bundled Helpers
#                       (rage/rsign/passeport-core) with the hardened runtime and
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

echo "==> Bundling permissive CLI toolchain (rage, rsign2) into Contents/Helpers"
"$ROOT/scripts/bundle-tooling.sh" "$APP"
[ -f "$ROOT/NOTICE" ] && cp "$ROOT/NOTICE" "$APP/Contents/Resources/NOTICE" || true

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  echo "==> Signing app with the hardened runtime (preserving entitlements)"
  # The app was built unsigned (CODE_SIGNING_ALLOWED=NO), so no entitlements are
  # embedded. Regenerate the one entitlement the app declares —
  # keychain-access-groups — with its build variables expanded, or the signed
  # app cannot read the data-protection keychain holding the seed
  # (errSecMissingEntitlement on cold launch). Xcode normally expands
  # $(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER); do it by hand here.
  TEAM_ID="$(printf '%s' "$CODESIGN_IDENTITY" | sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p')"
  BUNDLE_ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist" 2>/dev/null || true)"
  ENT_ARGS=()
  if [ -n "$TEAM_ID" ] && [ -n "$BUNDLE_ID" ]; then
    ENT="$(mktemp -t passeport-entitlements).plist"
    cat > "$ENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>keychain-access-groups</key>
  <array><string>${TEAM_ID}.${BUNDLE_ID}</string></array>
</dict></plist>
EOF
    ENT_ARGS=(--entitlements "$ENT")
    echo "    entitlements: keychain-access-groups = ${TEAM_ID}.${BUNDLE_ID}"
  else
    echo "warning: could not derive Team ID / bundle id — signing WITHOUT keychain-access-groups; the seed keychain will be inaccessible on the distributed app. Use a 'Name (TEAMID)' Developer ID identity." >&2
  fi
  # Helpers were already signed inside-out by bundle-tooling.sh; sign the app
  # (main executable + bundle seal) WITHOUT --deep so their signatures are kept.
  codesign --force --options runtime --timestamp "${ENT_ARGS[@]}" -s "$CODESIGN_IDENTITY" "$APP"
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
