import AppKit
import Foundation
import ServiceManagement

@MainActor
final class AppModel: ObservableObject {
    @Published var pgpUserID: String
    @Published private var savedPGPUserID: String
    @Published private(set) var identity: DerivedIdentity?
    @Published private(set) var hasSeed: Bool
    @Published private(set) var status = "Ready"
    @Published private(set) var isBusy = false
    @Published var showingPrivateMaterial = false
    @Published private(set) var bridgeRunning = false
    @Published var backgroundLauncherInstalled = LaunchAgentInstaller.isInstalled
    @Published var recoveryPhrase: String?
    @Published private(set) var contractWarning: String?
    @Published var launchAtLogin: Bool {
        didSet { applyLaunchAtLogin() }
    }
    @Published var confirmEachOperation: Bool {
        didSet {
            UserDefaults.standard.set(confirmEachOperation, forKey: "PasseportConfirmEachOperation")
            applyBridgePolicy()
        }
    }
    @Published var requireTouchIDPerOperation: Bool {
        didSet {
            UserDefaults.standard.set(requireTouchIDPerOperation, forKey: "PasseportRequireTouchIDPerOperation")
            applyBridgePolicy()
        }
    }

    private let core = CoreClient()
    private static let pgpUserIDKey = "PasseportPGPUserID"

    init() {
        let userID = AppModel.loadPGPUserID()
        pgpUserID = userID
        savedPGPUserID = userID
        hasSeed = SeedStore.seedExists()
        launchAtLogin = SMAppService.mainApp.status == .enabled
        confirmEachOperation = UserDefaults.standard.bool(forKey: "PasseportConfirmEachOperation")
        requireTouchIDPerOperation = UserDefaults.standard.bool(forKey: "PasseportRequireTouchIDPerOperation")
        applyBridgePolicy()
    }

    private static var defaultPGPUserID: String {
        "\(NSUserName()) <\(NSUserName())@localhost>"
    }

    private static func loadPGPUserID() -> String {
        let saved = UserDefaults.standard.string(forKey: pgpUserIDKey)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let saved, !saved.isEmpty {
            return saved
        }
        return defaultPGPUserID
    }

    /// True when the field differs from what is persisted.
    var pgpUserIDHasUnsavedChanges: Bool {
        pgpUserID.trimmingCharacters(in: .whitespacesAndNewlines) != savedPGPUserID
    }

    func savePGPUserID() {
        let trimmed = pgpUserID.trimmingCharacters(in: .whitespacesAndNewlines)
        let value = trimmed.isEmpty ? AppModel.defaultPGPUserID : trimmed
        pgpUserID = value
        savedPGPUserID = value
        UserDefaults.standard.set(value, forKey: Self.pgpUserIDKey)
        status = "OpenPGP user ID saved"
    }

    func refreshSeedPresence() {
        hasSeed = SeedStore.seedExists()
    }

    private func applyBridgePolicy() {
        let confirm = confirmEachOperation
        let touch = requireTouchIDPerOperation
        Task { await ScdBridge.shared.setPolicy(confirmEachOperation: confirm, requireTouchIDPerOperation: touch) }
    }

    private func applyLaunchAtLogin() {
        do {
            if launchAtLogin {
                if SMAppService.mainApp.status != .enabled {
                    try SMAppService.mainApp.register()
                }
            } else {
                if SMAppService.mainApp.status == .enabled {
                    try SMAppService.mainApp.unregister()
                }
            }
        } catch {
            status = "Could not update login item: \(error.localizedDescription)"
        }
    }

    func lock() {
        Task { @MainActor in
            await self.lockAsync()
        }
    }

    private func lockAsync() async {
        self.identity = nil
        self.showingPrivateMaterial = false
        await SeedStore.clearCachedSeed()
        self.status = "Locked"
    }

    /// Onboarding: mint a fresh random seed, derive its keys, and surface the
    /// recovery phrase so the user backs it up right away (wallet-style).
    func createNewIdentity() {
        runBusy("Creating a new identity") { [self] in
            let seed = try await SeedStore.createRandomSeed()
            self.hasSeed = true
            let phrase = try SeedBackup.recoveryPhrase(seed: seed)
            try await self.deriveFromCachedSeed()
            self.recoveryPhrase = phrase
            self.status = "New identity created — write down your recovery phrase"
        }
    }

    func deriveKeys() {
        runBusy("Deriving keys") { [self] in
            try await self.deriveFromCachedSeed()
            self.status = "Keys derived from your seed"
        }
    }

    /// Unlock the seed (Touch ID once per session) and derive the identity.
    private func deriveFromCachedSeed() async throws {
        let prf = try await SeedStore.prf(salt: SeedStore.rootSalt)
        self.identity = try await self.core.derive(
            prf: prf,
            userID: self.pgpUserID.trimmedNonEmpty(defaultValue: "Passeport <passeport@localhost>"),
            sshComment: "passeport"
        )
    }

    func resetSeed() {
        runBusy("Removing the seed") {
            try await SeedStore.deleteSeed()
            await MainActor.run {
                self.hasSeed = false
                self.identity = nil
                self.showingPrivateMaterial = false
                self.status = "Seed removed from this Mac"
            }
        }
    }

    /// Verify the derivation contract at launch: re-derive from a fixed test
    /// PRF and confirm the fingerprint still matches the baked-in baseline. A
    /// mismatch means a dependency changed the output and derived keys would
    /// no longer match other devices — a serious, silent failure otherwise.
    func runContractSelfTest() {
        Task.detached(priority: .utility) {
            let passed = DeterminismCheck.run()
            await MainActor.run {
                if case .failed(let message) = passed {
                    self.contractWarning = message
                }
            }
        }
    }

    /// Bring the socket up on launch so gpg works whenever the app runs.
    /// Only binds the socket; no seed access until gpg requests an operation.
    func startBridgeIfNeeded() {
        Task { @MainActor in
            guard !(await ScdBridge.shared.isRunning) else {
                self.bridgeRunning = true
                return
            }
            do {
                try await ScdBridge.shared.start()
                self.bridgeRunning = true
            } catch {
                self.status = error.localizedDescription
            }
        }
    }

    func toggleBackgroundLauncher() {
        runBusy(backgroundLauncherInstalled ? "Removing background launcher" : "Installing background launcher") { [self] in
            if LaunchAgentInstaller.isInstalled {
                // Stopping our socket first frees the path for launchctl bootout.
                await ScdBridge.shared.stop()
                self.bridgeRunning = false
                try LaunchAgentInstaller.uninstall()
                self.status = "Background launcher removed"
            } else {
                await ScdBridge.shared.stop()
                self.bridgeRunning = false
                try LaunchAgentInstaller.install()
                self.status = "Background launcher installed — gpg will start Passeport on demand"
            }
            self.backgroundLauncherInstalled = LaunchAgentInstaller.isInstalled
        }
    }

    func toggleBridge() {
        runBusy(bridgeRunning ? "Stopping GnuPG bridge" : "Starting GnuPG bridge") { [self] in
            if await ScdBridge.shared.isRunning {
                await ScdBridge.shared.stop()
                self.bridgeRunning = false
                self.status = "GnuPG bridge stopped"
            } else {
                try await ScdBridge.shared.start()
                self.bridgeRunning = true
                self.status = "GnuPG bridge running — configure gpg-agent to use it"
            }
        }
    }

    func configureGnuPG() {
        guard let identity else {
            status = "Derive keys first, then configure GnuPG"
            return
        }
        runBusy("Configuring GnuPG") { [self] in
            if !(await ScdBridge.shared.isRunning) {
                try await ScdBridge.shared.start()
                self.bridgeRunning = true
            }
            let helperPath = try CoreLocator.helperURL().path
            let socketPath = ScdBridge.socketURL.path
            let publicKey = identity.pgp.publicKey
            let result = try await Task.detached(priority: .userInitiated) {
                try GnuPGConfigurator.configure(
                    publicKeyArmored: publicKey,
                    socketPath: socketPath,
                    helperPath: helperPath
                )
            }.value
            self.status = "GnuPG configured. For SSH: export SSH_AUTH_SOCK=\(result.sshAuthSock)"
        }
    }

    func revealRecoveryPhrase() {
        runBusy("Unlocking recovery phrase") { [self] in
            let seed = try await SeedStore.revealSeed()
            let phrase = try SeedBackup.recoveryPhrase(seed: seed)
            self.recoveryPhrase = phrase
            self.status = "Write down these 24 words and store them offline"
        }
    }

    func dismissRecoveryPhrase() {
        recoveryPhrase = nil
    }

    func restore(fromPhrase phrase: String) {
        runBusy("Restoring from recovery phrase") { [self] in
            let seed = try SeedBackup.seed(fromPhrase: phrase)
            try await SeedStore.restoreSeed(seed)
            self.hasSeed = true
            self.showingPrivateMaterial = false
            try await self.deriveFromCachedSeed()
            self.status = "Identity restored from your recovery phrase"
        }
    }

    func saveRevocationCertificate() {
        runBusy("Preparing revocation certificate") { [self] in
            let prf = try await SeedStore.prf(salt: SeedStore.rootSalt)
            let userID = self.pgpUserID.trimmedNonEmpty(defaultValue: "Passeport <passeport@localhost>")
            let cert = try SeedBackup.revocationCertificate(prf: prf, userID: userID)
            self.save(text: cert, suggestedName: "passeport-revocation.asc")
        }
    }

    func configureGitSigning() {
        guard let identity else {
            status = "Derive keys first, then set up git signing"
            return
        }
        runBusy("Configuring git commit signing") {
            let gpgPath = try GnuPGConfigurator.gpgPath()
            let result = try await Task.detached(priority: .userInitiated) {
                try GitConfigurator.configure(fingerprint: identity.pgp.fingerprint, gpgPath: gpgPath)
            }.value
            await MainActor.run {
                self.status = "git will now sign commits with \(result.signingKey.suffix(16))"
            }
        }
    }

    func copy(_ value: String, label: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
        status = "Copied \(label)"
    }

    func exportPublicBundle() {
        guard let identity else { return }
        save(text: identity.publicBundle, suggestedName: "passeport-public-keys.txt")
    }

    func exportPrivateBundle() {
        guard let identity else { return }
        save(text: identity.privateBundle, suggestedName: "passeport-private-keys.txt")
    }

    private func runBusy(_ message: String, operation: @escaping () async throws -> Void) {
        guard !isBusy else { return }
        isBusy = true
        status = message

        Task {
            do {
                try await operation()
            } catch {
                status = error.localizedDescription
            }
            isBusy = false
        }
    }

    private func save(text: String, suggestedName: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.canCreateDirectories = true

        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            status = "Exported \(url.lastPathComponent)"
        } catch {
            status = error.localizedDescription
        }
    }
}

private extension String {
    func trimmedNonEmpty(defaultValue: String) -> String {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? defaultValue : trimmed
    }
}
