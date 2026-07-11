# Passeport

Passeport is a native macOS app that derives stable SSH, OpenPGP, age, and
Minisign keys from one 24-word recovery phrase.

The root seed is stored only on the Mac in a private local vault, optionally
encrypted with a password. The recovery phrase is the portable backup:
restoring the same phrase recreates the same identity.

Passeport is not a hardware security key. The seed exists in software and can
reconstruct every derived key. Use a fresh Passeport phrase and never reuse a
cryptocurrency wallet phrase.

## Features

- Native SwiftUI app with a menu-bar presence and optional hidden Dock icon.
- One device-local seed represented by a standard 24-word BIP39 mnemonic.
- Optional password encryption for the local seed vault.
- Manual lock plus configurable sleep and inactivity auto-lock.
- Optional confirmation for every private operation.
- Recovery-phrase verification drills and configurable verification reminders.
- OpenPGP revocation-certificate generation.
- Local operation audit log and native macOS Help Book.

### Integrations

- **SSH:** a native SSH agent serving the OpenPGP authentication subkey.
- **OpenPGP (GNU-free):** a bundled, single-identity `passeport-gpg` command for
  signing, verification, encryption to the Passeport identity, and decryption.
- **OpenPGP (Pluggable Scdaemon):** optional integration with an existing GnuPG installation.
- **Git signing:** SSH or OpenPGP commit and tag signing.
- **age:** `passeport-age` for standard age encryption and app-approved decryption.
- **Minisign:** `passeport-minisign` for app-approved signing and public verification.

Each integration has Configure, Test, Repair, and Remove controls. Test performs
a real cryptographic round trip. Passeport records configuration it replaces so
removal can restore the previous Git and GnuPG values safely.

## Requirements

- macOS 15 or newer.
- Xcode with the Swift 6 toolchain.
- Rust toolchain for building `passeport-core`.
- An existing GnuPG installation only when using Pluggable Scdaemon.

Passeport does not require iCloud or an in-app account.

## Build

```sh
open Passeport.xcodeproj
```

Select the `Passeport` scheme and press Run. The Xcode build phase compiles the
Rust helper and places it inside the app bundle.

Command-line Debug build:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project Passeport.xcodeproj \
  -scheme Passeport -configuration Debug \
  -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build
```

Run the Rust tests with:

```sh
cargo test --manifest-path crates/passeport-core/Cargo.toml
```

The shared Xcode scheme also includes a small `PasseportUITests` smoke suite.
It launches a signed Debug build with `--accessibility-audit`, so run it on a
development Mac with `xcodebuild test -project Passeport.xcodeproj -scheme Passeport`.
CI runs the pure Swift unit target unsigned and leaves the signing-dependent UI
suite to signed local builds.

## Packaging

`scripts/make-dmg.sh` builds the app and creates `dist/Passeport.dmg`.

```sh
scripts/make-dmg.sh
```

The identity vault is independent of code-signing identity, so local
and unsigned builds retain the same seed across upgrades. Developer ID signing
and notarization remain strongly recommended for publisher authenticity and a
normal Gatekeeper installation experience.

## Identity and recovery

Passeport generates a random 32-byte seed. Its 24-word BIP39 encoding is the
recovery phrase. The phrase format is standard BIP39, but Passeport’s derived
Ed25519 and Curve25519 keys are not cryptocurrency wallet keys.

An optional password can be chosen when creating or restoring an identity to
encrypt the local vault. It is not part of key derivation.

To prepare an identity:

1. Create a new identity or restore a recovery phrase.
2. Write the phrase down offline and complete the verification drill.
3. Save the OpenPGP revocation certificate.
4. Configure and test each required integration.

If the recovery phrase or seed may be exposed, replace the identity. OpenPGP
revocation does not revoke SSH, age, or Minisign keys; replace those keys on
every service where they were registered.

## Security model

The seed is stored in `~/Library/Application Support/Passeport/identity.vault`.
Its containing directory is mode `0700` and the vault file is mode `0600`. If a
password is configured, it derives an encryption key using PBKDF2-HMAC-SHA512;
the vault is then authenticated and encrypted with ChaCha20-Poly1305. Without a
password, the seed is stored directly in the private vault file. Derived private
material is held in memory while the identity is unlocked and cleared when
Passeport locks.

Private operations travel through the running app and follow the configured
approval policy. Installed command-line wrappers contain socket and public-key
configuration, not the seed.

- Anyone with the recovery phrase or readable vault seed can reconstruct the identity.
- Malware running with sufficient access to the user session remains in scope.
- A stolen, unlocked Mac may expose an active identity.
- Use a hardware token when non-extractable keys are required.

The exact compatibility contract is documented in [DERIVATION.md](DERIVATION.md).

## Installed commands and files

Configured commands are linked under `~/.local/bin`:

- `passeport-gpg`
- `passeport-age`
- `age-plugin-passeport`
- `passeport-minisign`

Optional `gpg`, `age`, and `minisign` aliases are installed only when Passeport
can do so without replacing an unrelated command. The Minisign public key is
written to `~/.minisign/passeport.pub`.

Use Settings → Diagnostics & cleanup → Remove Passeport Configuration to remove
Passeport-owned integration files and restore managed configuration. This does
not delete the seed.

## Credits

The Passeport logo comes from the
[Solar Bold Icons](https://www.svgrepo.com/svg/526073/passport) collection on
SVG Repo and is used under the
[CC Attribution license](https://www.svgrepo.com/page/licensing/#CC%20Attribution).
