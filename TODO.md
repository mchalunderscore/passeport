# TODO

## Do immediately

- [ ] **Operation audit log** — in-app, append-only list of every private-key
  operation: timestamp, operation type, requesting client, and what was signed
  (parsed git commit summary, SSH target when recoverable). The approval prompt
  guards in the moment; the log catches silent misuse after the fact. Every
  operation already funnels through the bridge, so hook it there.
- [ ] **Secure Enclave–wrapped seed at rest** — encrypt the keychain-stored
  seed with a Secure Enclave key that requires biometry, instead of the
  app-level LocalAuthentication gate. Upgrades Touch ID from an app-level check
  toward hardware-enforced, without losing recovery-phrase portability (the SE
  key only wraps the seed on this device).
- [ ] **Optional BIP39 passphrase ("25th word")** — domain-separates the
  identity so a leaked paper phrase alone is no longer the whole identity.
  Changes the derivation contract: must be versioned/opt-in and documented in
  DERIVATION.md.
- [ ] **Auto-lock policy** — clear the in-memory seed on sleep, screen lock,
  or N minutes idle (configurable). Directly shrinks the stolen-unlocked-Mac
  window called out in the security model.
- [ ] **Backup drill** — periodic "verify your recovery phrase" flow that asks
  for a few random words of the phrase and checks them without ever displaying
  it. Guards against the paper backup quietly rotting.

## Future

- [ ] **Native SSH agent** — implement the ssh-agent protocol directly on a
  socket so SSH works without GnuPG installed at all. Reuses the auth subkey
  and the existing approval/Touch ID plumbing; removes the GnuPG dependency
  for the most common use case.
- [ ] **SSH commit signing** — a "Set Up Git Signing (SSH)" option
  (`gpg.format=ssh`) next to the existing GPG one, including writing the
  `allowed_signers` file so `git log --show-signature` verifies locally.
- [ ] **age encryption key** — derive an X25519 age identity and ship an
  `age-plugin-passeport`, giving Touch ID-gated file encryption to the age
  ecosystem.
- [ ] **Distribution polish** — Sparkle auto-updates for the DMG and a
  Homebrew cask. For a security tool, an update channel is a security feature.
