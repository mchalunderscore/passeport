# TODO

- [ ] **Establish a stable signed release contract.** Do not publish the current
  unsigned DMG as fully functional: the data-protection keychain requires a
  stable signing principal and entitlements. Use one Developer ID identity for
  public releases, make release publication fail when credentials are absent,
  and retain unsigned builds only as an explicitly local-development path. An
  arbitrary or per-build signer is not sufficient because changing signing
  identity can orphan existing keychain items.
