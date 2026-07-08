#!/usr/bin/env bash
#
# Build Passeport.app and package it into a distributable dist/Passeport.dmg.
#
# Modes (chosen by environment variables):
#
#   Ad-hoc (default — no Apple Developer account needed):
#       scripts/make-dmg.sh
#     Produces a DMG that runs, but Gatekeeper will warn on first launch and
#     the synced-keychain feature won't work (the keychain-access-group
#     entitlement is only valid under a real signing identity). Good for a
#     quick "does it launch" build, not for real distribution.
#
#   Developer ID (recommended for GitHub releases):
#       SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
#       NOTARY_PROFILE="passeport-notary" \
#       scripts/make-dmg.sh
#     Signs with hardened runtime + secure timestamp, notarizes via
#     notarytool, staples the ticket, and packages the DMG. Users can then
#     double-click with no Gatekeeper friction.
#
#   Set up the notary profile once with:
#       xcrun notarytool store-credentials passeport-notary \
#         --apple-id you@example.com --team-id TEAMID --password <app-specific-pw>

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIGURATION="${CONFIGURATION:-Release}"
DERIVED_DATA="${DERIVED_DATA:-/tmp/passeport-release-dd}"
APP="$ROOT/dist/Passeport.app"
DMG="$ROOT/dist/Passeport.dmg"
ENTITLEMENTS="$ROOT/Resources/Passeport.entitlements"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"          # "-" = ad-hoc
VOLNAME="Passeport"

if [ -z "${DEVELOPER_DIR:-}" ] && [ -d /Applications/Xcode.app/Contents/Developer ]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi

signed_release() { [ "$SIGN_IDENTITY" != "-" ]; }

echo "==> Building $CONFIGURATION ($([ "$SIGN_IDENTITY" = "-" ] && echo "ad-hoc" || echo "Developer ID"))"
BUILD_ARGS=(
  -project "$ROOT/Passeport.xcodeproj"
  -scheme Passeport
  -configuration "$CONFIGURATION"
  -derivedDataPath "$DERIVED_DATA"
  CODE_SIGN_STYLE=Manual
  CODE_SIGN_IDENTITY="$SIGN_IDENTITY"
)
if signed_release; then
  BUILD_ARGS+=(ENABLE_HARDENED_RUNTIME=YES DEVELOPMENT_TEAM="${TEAM_ID:-}")
else
  # Ad-hoc: drop provisioning and the app-identifier entitlement (which would
  # otherwise require a provisioning profile). The synced-keychain feature is
  # non-functional in this mode — it's for a quick launch test only.
  BUILD_ARGS+=(
    DEVELOPMENT_TEAM=
    CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO
    CODE_SIGN_ENTITLEMENTS=
    PROVISIONING_PROFILE_SPECIFIER=
  )
fi
xcodebuild "${BUILD_ARGS[@]}" build

BUILT="$DERIVED_DATA/Build/Products/$CONFIGURATION/Passeport.app"
rm -rf "$APP"
mkdir -p "$ROOT/dist"
ditto "$BUILT" "$APP"
[ -x "$(command -v xattr)" ] && xattr -cr "$APP" || true

if signed_release; then
  echo "==> Signing for distribution (hardened runtime + secure timestamp)"
  # Sign inside-out: the bundled helper first, then the app bundle.
  codesign --force --options runtime --timestamp \
    --sign "$SIGN_IDENTITY" "$APP/Contents/Helpers/passeport-core"
  codesign --force --options runtime --timestamp \
    --entitlements "$ENTITLEMENTS" --sign "$SIGN_IDENTITY" "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP"

  if [ -n "${NOTARY_PROFILE:-}" ]; then
    echo "==> Notarizing (this uploads the app to Apple and waits)"
    ZIP="$ROOT/dist/Passeport-notarize.zip"
    ditto -c -k --keepParent "$APP" "$ZIP"
    xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$APP"
    rm -f "$ZIP"
  else
    echo "==> NOTARY_PROFILE not set — skipping notarization (users will see Gatekeeper warnings)"
  fi
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
if signed_release && [ -n "${NOTARY_PROFILE:-}" ]; then
  echo "Signed + notarized — ready to attach to a GitHub release."
else
  echo "Ad-hoc/unsigned — fine for testing; use SIGN_IDENTITY + NOTARY_PROFILE for release."
fi
