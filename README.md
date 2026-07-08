# Passeport

Passeport is a macOS-native app for deriving stable SSH and OpenPGP identity
keys from a **24-word recovery phrase** you control.

**In one line:** your whole identity is a BIP39 seed phrase — the same standard
a crypto wallet uses. Write the 24 words down once; they reconstruct your SSH
and OpenPGP keys on any Mac, deterministically. It's less secure than a
hardware token like a YubiKey, but far more convenient and cloud-free: nothing
syncs anywhere, the secret never leaves your machine, and the backup is a phrase
you keep, not an account you trust.

The root secret is a random 32-byte seed, stored **device-local** in the
keychain and unlocked behind Touch ID. Portability is the recovery phrase, not
sync — the seed's raw entropy *is* a standard BIP39 mnemonic, so you can back it
up the way people back up wallet phrases (paper, a steel plate, etc.) and
restore it on another Mac. Key-specific seeds are derived with HKDF-SHA256, and
generated private keys stay in memory unless you explicitly export them.

> The keys derived from a Passeport phrase are Ed25519/Curve25519 (SSH + PGP),
> *not* a wallet's secp256k1 keys — the phrase format is interoperable, the
> derived keys are not. Use a fresh Passeport phrase; don't reuse a wallet seed.

## Current Shape

- SwiftUI app for the native macOS interface.
- Device-local root seed, unlocked once per session behind a
  LocalAuthentication (Touch ID or password) prompt.
- Small bundled Rust helper for SSH/OpenPGP serialization and a virtual
  OpenPGP smartcard (scdaemon) that serves the identity to gpg-agent.
- The 24-word BIP39 recovery phrase is the identity's backup *and* the way to
  move it between Macs, plus an OpenPGP revocation certificate.
- A derivation self-test at launch guards against dependency drift changing
  the derived keys.
- One-click GnuPG and git commit-signing setup; optional per-operation
  approval prompts and an on-demand background launcher.

## Requirements

- macOS 15 or newer. No iCloud or Apple ID sign-in is required.
- Xcode with the Swift 6 toolchain.
- Rust toolchain for the key helper.

## Build

Use Xcode:

```sh
open Passeport.xcodeproj
```

Select the `Passeport` scheme and press Run. The app needs no special
entitlements or provisioning; no Apple Developer account is required to build
or run it.

## Packaging a release DMG

`scripts/make-dmg.sh` builds `Passeport.app` and packages it into
`dist/Passeport.dmg` (with a drag-to-`/Applications` symlink).

```sh
scripts/make-dmg.sh
```

Then attach the DMG to a GitHub release:

```sh
gh release create v0.1.0 dist/Passeport.dmg --title "Passeport 0.1.0" --notes "…"
```

The script also supports signing and notarizing via the `SIGN_IDENTITY` and
`NOTARY_PROFILE` environment variables (see the header of
[scripts/make-dmg.sh](scripts/make-dmg.sh)); an unsigned build is fully
functional but shows a Gatekeeper warning on first launch (right-click →
Open once).

## Security Model

Passeport makes a deliberate trade: **weaker than a hardware token, much more
convenient.** Be clear-eyed about which side of that trade you want before you
rely on it.

The trust model is a **seed phrase you control** — like a crypto wallet. Your
identity is 24 words. Whoever has the phrase (or the unlocked seed on a running
machine) has the identity; nobody else does, and it depends on no cloud account.

**What you give up versus a YubiKey / Secure Enclave key:**

- The seed is **extractable** — it's a value in software, not bound to
  tamper-resistant hardware. A YubiKey's private key can never leave the
  device; this seed exists as bytes and can be read by anything running as you
  while the keychain is unlocked.
- Touch ID is an **app-level** gate (a LocalAuthentication check before the
  seed is used), not enforced by the keychain hardware. The optional
  per-operation confirmation adds a second app-level check, still not
  hardware-enforced.
- Your paper phrase is only as safe as where you keep it. A photographed or
  leaked phrase is the whole identity.

**What you get in return:**

- **No cloud, no account.** The seed lives only on your Mac — it never touches
  iCloud or any server. There is no "compromise the Apple account → get the
  seed" path, because there's no synced copy.
- **Deterministic and portable.** The whole identity is a function of one
  32-byte seed, encoded as a standard **BIP39** phrase. Write the 24 words
  down; they reconstruct the exact same SSH and PGP keys on any Mac, and you
  can store them with the same tools people use for wallet seeds.
- **A real upgrade over a bare key file.** The alternative most people use is a
  private key sitting in `~/.ssh` or `~/.gnupg`, readable by any process that
  runs as you. Here the key material never lands on disk, stays in memory, is
  gated behind Touch ID, and flows to `gpg`/`ssh` through a virtual smartcard
  rather than living in their keyrings.

**Rule of thumb:** if your threat model includes malware with your user
privileges or a stolen-and-unlocked Mac, use a hardware token. If you want
SSH/PGP that you can reconstruct anywhere from a phrase you keep offline,
without babysitting key files or trusting a cloud, Passeport is a strict
improvement in both security and ergonomics.

The seed, its HMAC-derived root, and derived private keys are kept in process
memory and cleared when the app is locked.

The derivation contract is documented in [DERIVATION.md](DERIVATION.md).

## Using the identity with GnuPG and SSH

Passeport can serve the derived identity to `gpg-agent` as a virtual OpenPGP
smartcard, so `gpg` and `ssh` use it without the private keys ever entering
their keyrings. Private operations run inside the app behind the Touch ID
gate; the helper that gpg-agent talks to holds no key material.

The quick path:

1. Derive your keys (**Derive Keys**).
2. Click **Configure GnuPG**. This starts the bridge, writes the scdaemon
   wrapper and `gpg-agent.conf` (`scdaemon-program` + `enable-ssh-support`,
   backing up any existing config), imports the public key, and creates the
   card stubs. The status line then shows the `SSH_AUTH_SOCK` to export.
3. For SSH, point your shell at gpg-agent's ssh socket:

   ```sh
   export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
   ssh-add -L   # lists the authentication subkey as an ssh-ed25519 key
   ```

Enable **Start bridge at login** so the card is available whenever you are
logged in; a menu-bar item shows bridge status and can start/stop it or
re-run configuration. The `gpg` sign/encrypt/authenticate and `ssh` flows run
against the virtual card, prompting for Touch ID via the app on first use per
session.

Passeport looks for `gpg` on `PATH` and in common locations
(`/opt/homebrew/bin`, `/usr/local/bin`); set `PASSEPORT_GPG` to override.

### Manual configuration

If you prefer to wire it up yourself, the wrapper and config that
**Configure GnuPG** writes are:

```text
# ~/.gnupg/gpg-agent.conf
scdaemon-program /path/to/passeport-scd
enable-ssh-support
```

```sh
# passeport-scd wrapper
#!/bin/bash
export PASSEPORT_SCD_SOCKET="$HOME/Library/Application Support/Passeport/scd.sock"
exec /Applications/Passeport.app/Contents/Helpers/passeport-core scd
```

then `gpgconf --kill all`, `gpg --import passeport-public-keys.txt`, and
`gpg --card-status`.

### Git commit signing

**Set Up Git Commit Signing** points git at the same gpg and enables signing:
`gpg.program`, `user.signingkey` (the primary fingerprint), `commit.gpgsign`,
and `tag.gpgsign`. New commits and tags are then signed by the virtual card.

### Backup & recovery

- **Recovery Phrase** reveals the 24-word BIP39 phrase for the root seed
  (behind Touch ID). Write it down offline — since the seed is device-local, it
  is the only way to reconstruct the identity if this Mac is lost, and the way
  to set the same identity up on another Mac.
- **Restore…** rewrites the seed from a phrase on a new machine.
- **Save Revocation Certificate** exports a standard OpenPGP revocation
  certificate; import it with `gpg --import` to revoke the key even without the
  seed.

### Operation approval and availability

- **Confirm each signature/decryption** prompts before every private
  operation, showing what is being signed — a check against a compromised
  gpg-agent using the key silently. **Require Touch ID for each operation**
  re-authenticates per operation instead of once per session.
- **Start Passeport on demand (background launcher)** installs a LaunchAgent
  that socket-activates the app, so gpg/ssh work even if the app was not
  already running.
