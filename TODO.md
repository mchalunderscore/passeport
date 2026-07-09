# TODO

## Future

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

  **This is ADDITIVE to scdaemon mode, not a replacement — the two coexist.**
  Both are just frontends over the shared `ScdBridge` backend (seed + Touch ID
  + approval + audit), which every consumer already funnels through:
      Mode 1 (today):  user gpg → user gpg-agent → scdaemon(shim) → ScdBridge → seed
      Mode 2 (opt-in): chameleon gpg → Passeport gpg-agent ──────→ ScdBridge → seed
  Mode 1 keeps Passeport as one card alongside the user's own keys in their
  `~/.gnupg`. Mode 2 is a self-contained, Passeport-identity-only stack. They
  don't collide because Mode 2 lives in its **own GNUPGHOME** with its own agent
  socket (gpg-agent sockets are per-GNUPGHOME), and the bundled `gpg` is invoked
  with `GNUPGHOME` set so it never shadows the system `gpg`. Same seed-derived
  identity through both; shared `PublicCardCache`/audit with no conflict; two
  agents just serialize on the bridge. Each is its own opt-in "Configure…"
  button. Mode 2's agent deliberately serves only the Passeport identity (keys
  are seed-derived, never imported) — anyone needing a full keyring stays in
  Mode 1.

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

---

## Done

Shipped and cleared from the active list (git history has the detail):
operation audit log · Secure Enclave–gated seed at rest · optional BIP39
passphrase ("25th word") · auto-lock policy · backup drill · native SSH agent ·
SSH commit signing · `age-plugin-passeport` encryption. The two-toolchain
(Stack A / Stack B) architecture these completed is captured in
[[passeport-scd-architecture]].
