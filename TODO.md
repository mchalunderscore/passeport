# TODO

## Do immediately

- [x] **Operation audit log** — in-app, append-only list of every private-key
  operation: timestamp, operation type, requesting client, and what was signed
  (parsed git commit summary, SSH target when recoverable). The approval prompt
  guards in the moment; the log catches silent misuse after the fact. Every
  operation already funnels through the bridge, so hook it there.
- [x] **Secure Enclave–wrapped seed at rest** — encrypt the keychain-stored
  seed with a Secure Enclave key that requires biometry, instead of the
  app-level LocalAuthentication gate. The app now enforces this mode as
  non-optional: non-secure legacy storage modes are not supported.
- [x] **Optional BIP39 passphrase ("25th word")** — domain-separates the
  identity so a leaked paper phrase alone is no longer the whole identity.
  Shipped: never-stored passphrase, entered per unlock, mixed with the seed in
  the app before the PRF (Rust helper contract untouched) via
  PBKDF2-HMAC-SHA512(passphrase, "passeport-25th-word-v1"||seed, 210k). Empty
  passphrase = byte-identical to the old identity (opt-in, additive). A public
  HMAC verifier catches a mistyped passphrase before deriving wrong keys.
  Documented in DERIVATION.md. Chosen at create/restore; prompted at Derive
  Keys, and **on demand from the bridge** — a background gpg/ssh/age operation
  after auto-lock surfaces a passphrase panel (mirroring the approval dialog),
  unlocks, and proceeds, retrying on a wrong entry. Since every private op —
  gpg bridge, native SSH agent, age plugin — funnels through
  `ScdBridge.process`, they all inherit this. No manual re-unlock needed.
- [x] **Auto-lock policy** — clear the in-memory seed on sleep, screen lock,
  or N minutes idle (configurable). Directly shrinks the stolen-unlocked-Mac
  window called out in the security model.
- [x] **Backup drill** — periodic "verify your recovery phrase" flow that asks
  for a few random words of the phrase and checks them without ever displaying
  it. Guards against the paper backup quietly rotting.

## Future

- [x] **Native SSH agent** — implement the ssh-agent protocol directly on a
  socket so SSH works without GnuPG installed at all. Reuses the auth subkey
  and the existing approval/Touch ID plumbing; removes the GnuPG dependency
  for the most common use case. Serves identities from the public-card cache
  (no unlock) and routes signing through `ScdBridge.process`. "Configure SSH"
  points `~/.ssh/config` `IdentityAgent` at it. Surfaced and fixed a
  pre-existing bug: the secure seed lives in the data-protection keychain, so
  every SecItem query needs `kSecUseDataProtectionKeychain` or cold-launch
  seed detection/reads fail.
- [x] **SSH commit signing** — a "Set Up Git Signing (SSH)" option
  (`gpg.format=ssh`) next to the existing GPG one, including writing the
  `allowed_signers` file so `git log --show-signature` verifies locally. Signs
  through the native SSH agent; verified with `ssh-keygen -Y sign/verify`.
- [x] **age encryption key (`age-plugin-passeport`)** — Touch ID-gated file
  encryption without GnuPG, completing the second toolchain. Shipped: age
  plugin v1 state machine (recipient + identity), standard X25519 wrap,
  decryption via the bridge's ecdh op on OPENPGP.2. Reuses the cv25519
  encryption subkey (both stacks decrypt the same key). "Set Up age Encryption"
  installs the plugin wrapper and shows the recipient. Verified end-to-end with
  the real binaries (encrypt → decrypt round-trips the file key).

  Context: Passeport is one seed-derived identity behind two interchangeable
  toolchains, chosen by whether GnuPG is installed. Same three keys either way;
  SSH auth is byte-identical across both. This is the encryption half of the
  GnuPG-free stack (SSH agent = auth, SSH signing = auth, age = encryption).

  | Operation | Stack A: GnuPG | Stack B: GnuPG-free |
  | --- | --- | --- |
  | SSH auth | gpg-agent → auth subkey | native ssh-agent → auth subkey (done) |
  | Sign | gpg, `gpg.format=openpgp` | SSH sig, `gpg.format=ssh` → auth subkey |
  | Encrypt/decrypt | gpg → cv25519 encryption subkey | age → encryption subkey via this plugin |

  It is **Passeport-backed**, not ssh-backed. age cannot ride the ssh key or
  ssh-agent: ssh-agent only signs (no decrypt op), and age's own SSH support
  reads a private key *file*, which we don't expose. Instead the plugin reaches
  the private scalar through the bridge's existing X25519 ECDH on the cv25519
  encryption subkey (OPENPGP.2) — the same primitive gpg decryption already
  uses. So Stack B keeps the OpenPGP role split: auth key signs, encryption key
  decrypts. (Converting the Ed25519 auth key to X25519 for age is possible but
  needs a new bridge op and doubles up one key's roles — skip it; the
  encryption subkey is right there.)

  Build:
  - Implement age's plugin protocol (stdio state machine) as a new binary that
    calls the bridge for the recipient/identity ECDH, Touch ID-gated.
  - Reuse the existing cv25519 encryption subkey rather than deriving a fresh
    X25519 identity, so Stack A and Stack B decrypt with the same key material.
  - App UI to install the plugin and show the age recipient string.

  Caveat to document: the two stacks are **not interoperable** for encryption
  or signature *format*, even though the keys are shared — gpg ciphertext needs
  gpg to decrypt, age ciphertext needs age; OpenPGP and SSH signatures verify
  with different tools (GitHub's Verified badge accepts both). Users pick an
  encryption ecosystem and stay in it. SSH *auth* is the one thing identical
  across both. Depends on the native SSH agent (done); pairs with SSH commit
  signing to complete Stack B.
- [ ] **Distribution polish** — Sparkle auto-updates for the DMG and a
  Homebrew cask. For a security tool, an update channel is a security feature.

## Possibilities (unproven — spike before committing)

- [ ] **Bundle a CLI toolchain inside the app** — ship self-contained CLI
  binaries inside `Passeport.app/Contents/Helpers` (or a `.../Contents/CLI`
  subpath) so the user adds one directory to `PATH` and immediately has the
  tools, already wired to the Passeport identity. "Configure Shell" could print
  the exact `export PATH=…` line, mirroring the existing Configure GnuPG/SSH
  steps.

  **rage (`age` in Rust) — the clear keeper.** Apache-2.0/MIT, single static
  binary, no runtime deps, and it needs no agent — it just runs the age plugin
  we already built. Bundling it means age "just works" with zero install.
  (Complementary to, not a replacement for, doing age in-process via the `age`
  crate — that stays better for the app's own flows.)

  **sequoia-chameleon-gnupg — worth bundling ONLY together with a Passeport
  gpg-agent (see the next entry).** On its own it only replaces the `gpg`
  frontend, not `gpg-agent`, so alone it removes no GPLv3 dependency. But paired
  with Passeport standing in for gpg-agent, the chameleon becomes the permissive
  frontend of a fully GNU-free OpenPGP stack — which is the goal.

  **Finding (2026-07-09): the chameleon does not replace `gpg-agent`.** It
  reimplements the `gpg` frontend but still relies on GNU `gpg-agent` for
  private-key operations. So the chameleon *alone* removes no GPLv3 dependency —
  the value only materializes when Passeport also replaces `gpg-agent` (below).

  Notes (for whatever ends up bundled):
  - Every bundled Mach-O must be signed (hardened runtime) and notarized;
    confirm each tool notarizes cleanly.
  - Pin and vendor exact versions; a bundled crypto CLI is now Passeport's
    supply chain and its update surface.
  - Keep NOTICE/license files for anything shipped.

- [ ] **Passeport as `gpg-agent` — the keystone for a self-contained, GNU-free
  OpenPGP stack.** The goal: install Passeport and immediately have a
  derive-able **GPG + SSH + age** identity, no other software required. SSH
  (native agent) and age (plugin / in-process) already need no GNU code; this
  entry closes the last gap — the OpenPGP path still leans on GNU `gpg-agent`.

  What gpg-agent does, and why replacing it is tractable: it is the private-key
  custodian and Assuan hub `gpg` talks to. But most of its jobs don't apply to
  Passeport — passphrase cache/pinentry (Touch ID replaces it), ssh-agent
  (already replaced), key import/export/genkey (keys are seed-derived, never
  imported). The only parts that matter are the crypto (`PKSIGN`, `PKDECRYPT`)
  and key-existence queries (`HAVEKEY`, `KEYINFO`, `READKEY`) — all of which
  Passeport already implements one layer down in the scdaemon Assuan dialect
  ([scd.rs](crates/passeport-core/src/scd.rs)), keyed on keygrips we already
  compute and have verified against GnuPG (`keygrips_match_gpg`).

  The change: implement the **gpg-agent Assuan dialect** so `gpg` connects
  directly to a Passeport socket, collapsing two GNU processes out of the chain:
      today:    gpg → gpg-agent(GNU) → scdaemon(shim) → bridge → seed
      replaced: gpg → Passeport agent ───────────────→ bridge → seed
  Surface to cover: `HAVEKEY` / `KEYINFO[ --list]` / `READKEY` / `SETKEY` /
  `SETHASH` / `PKSIGN` / `PKDECRYPT` / `GETINFO` + the `OPTION`/session
  handshakes; stub the key-management verbs (`GENKEY`, `IMPORT`) since keys are
  derived. It is a *narrower* surface than full gpg-agent (no passphrase, ssh,
  or import), but matching `gpg`'s exact expectations is the hard part — expect
  the same finicky-protocol tail we hit with the scd shim (stale card model,
  DigestInfo stripping). Scope to `gpg` (OpenPGP) only; **do not** take on
  `gpgsm` / S/MIME.

  The payoff — the full bundle vision: **chameleon `gpg` (permissive frontend) +
  Passeport `gpg-agent` (this entry) + `rage` for age**, all shipped in a
  `Contents/` subpath on `PATH`. That is a complete, permissively-licensed,
  zero-install GPG/SSH/age toolchain with no GNU binaries and no GPLv3 — the
  thing that makes "just install Passeport" true for all three identities.

  Spike first: implement `HAVEKEY`/`KEYINFO`/`PKSIGN`/`PKDECRYPT` for the sign +
  auth keys, point a real `gpg` at the socket, and measure how close to happy it
  gets before committing to the full surface. See [[passeport-scd-architecture]].
