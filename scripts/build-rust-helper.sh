#!/bin/sh
set -eu

export PATH="$HOME/.cargo/bin:$PATH"

MANIFEST="$SRCROOT/crates/passeport-core/Cargo.toml"
HELPER_DIR="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Helpers"
HELPER_DST="$HELPER_DIR/passeport-core"
mkdir -p "$HELPER_DIR"

if [ "$CONFIGURATION" = "Release" ]; then
  ARM_TARGET=aarch64-apple-darwin
  INTEL_TARGET=x86_64-apple-darwin
  for target in "$ARM_TARGET" "$INTEL_TARGET"; do
    if ! rustup target list --installed | grep -qx "$target"; then
      echo "error: missing Rust target $target (run: rustup target add $target)" >&2
      exit 1
    fi
    cargo build --locked --release --manifest-path "$MANIFEST" --target "$target"
  done
  lipo -create \
    "$SRCROOT/crates/passeport-core/target/$ARM_TARGET/release/passeport-core" \
    "$SRCROOT/crates/passeport-core/target/$INTEL_TARGET/release/passeport-core" \
    -output "$HELPER_DST"
  ARCHS_BUILT="$(lipo -archs "$HELPER_DST")"
  echo "$ARCHS_BUILT" | grep -qw arm64
  echo "$ARCHS_BUILT" | grep -qw x86_64
else
  cargo build --locked --manifest-path "$MANIFEST"
  cp "$SRCROOT/crates/passeport-core/target/debug/passeport-core" "$HELPER_DST"
fi

if command -v xattr >/dev/null 2>&1; then
  xattr -cr "$TARGET_BUILD_DIR/$WRAPPER_NAME" 2>/dev/null || true
fi

if [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ] && [ "${CODE_SIGNING_ALLOWED:-YES}" != "NO" ]; then
  codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --timestamp=none "$HELPER_DST"
fi

# CFBundleVersion remains numeric for Apple tooling. Record source provenance
# separately so diagnostics can identify the exact commit that produced a build.
GIT_COMMIT="unknown"
if command -v git >/dev/null 2>&1; then
  GIT_COMMIT="$(git -C "$SRCROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
fi
BUILT_INFO_PLIST="$TARGET_BUILD_DIR/$INFOPLIST_PATH"
if [ -f "$BUILT_INFO_PLIST" ]; then
  if ! /usr/libexec/PlistBuddy -c "Set :PasseportGitCommit $GIT_COMMIT" "$BUILT_INFO_PLIST" 2>/dev/null; then
    /usr/libexec/PlistBuddy -c "Add :PasseportGitCommit string $GIT_COMMIT" "$BUILT_INFO_PLIST"
  fi
fi
