# TODO

- [ ] **Optionally add Developer ID distribution.** Passeport's identity vault
  works independently of code-signing identity, so unsigned builds retain their
  seed across upgrades. Developer ID signing and notarization would still give
  users Gatekeeper-verified publisher authenticity and a smoother installation
  experience, but are no longer required for storage correctness.
