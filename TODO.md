# TODO

## Future

- [ ] **Roll our own `age` — zero bundled binaries.** Replace the bundled `rage`
  binary with a self-contained `age` CLI in `passeport-core`, built on the
  pure-Rust **`age` crate as a library** (NOT a hand-rolled format reimplementation
  — same play as rpgp for gpg; hand-rolling the header MAC + ChaCha20-Poly1305
  STREAM is error-prone for no gain). Result: gpg, minisign, AND age are all our
  own pure-Rust CLIs, and the DMG bundles **no third-party binaries** — it ships
  only `passeport-core`. Distinction to keep in mind: this drops the bundled
  *binary*, not compiled-in pure-Rust *crates* (we already depend on rpgp,
  ed25519-dalek, chacha20poly1305, …).

  - New `age_cli.rs`: `-e -r <recipient> [-a]` encrypt (public), `-d` decrypt,
    `-o`/`-i`; dispatched by program name / `age` subcommand like gpg + minisign.
  - **Decrypt is gated** — a new `AgeDecrypt` bridge op mirroring `PgpDecrypt`:
    the op process derives the cv25519 scalar from the seed, the `age` crate
    decrypts, only plaintext returns. Seed never enters the CLI.
  - **Drop the `rage` bundle** — `bundle-tooling.sh` becomes empty/removed and
    `make-dmg` vendors nothing; `AgeConfigurator` installs a single `age` wrapper.
  - **Standard recipient** — switch the Passeport age recipient from the custom
    plugin recipient (`age1passeport…`) to a standard `age1…` X25519 recipient
    derived from the encryption subkey's public key, so any age tool can encrypt
    to you (public); only decryption needs Passeport.
  - **Keep `age-plugin-passeport`** as optional interop (it's ours, not bundled)
    so a user's own age/rage still decrypts via Touch ID — but no longer required.
  - Verify like the others: cargo round-trip (encrypt→decrypt) + decrypt a file
    that real `age`/`rage` encrypted to our standard recipient (interop).

- [x] **Distribution polish** — release DMG publication and install docs for a
  smoother manual update path (tagged workflow + checksums + release notes).

## Shipped in the GNU-free stack push (2026-07-09)

The items below started as spikes and are now **implemented and verified**
(cargo tests + real-gpg cross-verify + Swift typecheck). Kept with their original
analysis for context; the checkboxes reflect completion.

**What shipped:** seed-derived **minisign** signing (own HKDF domain
`passeport-minisign-v1`, gated through the bridge) with bundled `rsign2` for
verification; the **self-contained pure-Rust `gpg` drop-in (Mode 2)** —
front-to-back detached signing / verify-own / export / colon-listing that emits
git's `SIG_CREATED` status and produces signatures **the system gpg verifies**,
with no GnuPG binary; **rage + rsign2 bundled** into `Contents/Helpers` with
`age→rage` / `minisign→rsign` name-symlinks.

**Follow-up (2026-07-09, later):** minisign became a FULL own CLI (sign + verify
+ show-key, `src/minisign_cli.rs`) and the **`rsign2` bundle was dropped** as
redundant (we implement the whole minisign format); gpg gained
**encrypt/decrypt/clear-sign + `--help`** (decrypt via a gated `PgpDecrypt` op);
the Integrations UI was redesigned (status header + grouped `GroupBox` row-lists
with backend/method pickers), and the gpg/age availability chips were removed
(the gpg requirement is now contextual to the scdaemon / PGP options). So **only
`rage` is bundled today** — the "Roll our own age" item above drops that too.

**Chameleon rejected (do not revisit without new facts):**
`sequoia-chameleon-gnupg` is **GPL-3.0-or-later**, links native (L)GPL crypto
(Nettle/GMP), and needs an external `gpg-agent` — it fails the permissive,
self-contained, and GNU-free goals simultaneously. The Mode 2 rpgp drop-in
replaces it.

**gpg-agent Assuan dialect superseded:** rather than reimplement the finicky
gpg-agent protocol, Mode 2 does gpg **front-to-back** in one pure-Rust process
and delegates only the raw Ed25519 op to the bridge (via rpgp's
`SecretKeyTrait::create_signature` seam) — simpler, and no new Assuan. scdaemon
Mode 1 is untouched and still coexists.

## Possibilities (original analysis — now largely shipped, see above)

- [x] **Bundle a CLI toolchain inside the app** — ship self-contained CLI
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

- [x] **Passeport as `gpg-agent`** — *superseded: shipped as the Mode 2
  front-to-back gpg (above), not the Assuan dialect described below.* Original
  keystone plan for a self-contained, GNU-free
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

- [x] **Add minisign signing path as a non-GNU alternative.** Shipped:
  seed-derived Ed25519 minisign key (own HKDF domain), spec-exact `.minisig`
  output that `minisign`/`rsign` verify, signing gated through the bridge, and a
  `passeport-minisign <file>` shim. `rsign2` is bundled for verification.
## Done

Shipped and cleared from the active list (git history has the detail):
operation audit log · Secure Enclave–gated seed at rest · optional BIP39
passphrase ("25th word") · auto-lock policy · backup drill · native SSH agent ·
SSH commit signing · `age-plugin-passeport` encryption · self-contained
`minisign` CLI (sign + verify, seed-derived) · self-contained Mode 2 `gpg`
drop-in (front-to-back sign/verify/encrypt/decrypt/clear-sign, GNU-free) ·
bundled `rage` (the only third-party binary — slated to be replaced by our own
`age` CLI, see Future). The two-toolchain (Stack A / Stack B) architecture these
completed is captured in [[passeport-scd-architecture]].
