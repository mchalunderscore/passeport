import AppKit
import Foundation
import ServiceManagement

private final class AppModelMonitorState: @unchecked Sendable {
    var auditLogObserver: NSObjectProtocol?
    var workspaceObservers: [NSObjectProtocol] = []
    var distributedObservers: [NSObjectProtocol] = []
    var globalEventMonitor: Any?
    var localEventMonitor: Any?

    func clear() {
        if let globalEventMonitor {
            NSEvent.removeMonitor(globalEventMonitor)
        }
        if let localEventMonitor {
            NSEvent.removeMonitor(localEventMonitor)
        }
        if let observer = auditLogObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        workspaceObservers.forEach { observer in
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        distributedObservers.forEach { observer in
            DistributedNotificationCenter.default().removeObserver(observer)
        }

        globalEventMonitor = nil
        localEventMonitor = nil
        auditLogObserver = nil
        workspaceObservers.removeAll()
        distributedObservers.removeAll()
    }
}

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
            UserDefaults.standard.set(confirmEachOperation, forKey: Self.confirmEachOperationKey)
            applyBridgePolicy()
        }
    }
    @Published var requireTouchIDPerOperation: Bool {
        didSet {
            UserDefaults.standard.set(requireTouchIDPerOperation, forKey: Self.requireTouchIDPerOperationKey)
            applyBridgePolicy()
        }
    }
    @Published var autoLockOnSleep: Bool {
        didSet {
            UserDefaults.standard.set(autoLockOnSleep, forKey: Self.autoLockOnSleepKey)
            applyAutoLockPolicy()
        }
    }
    @Published var autoLockOnIdle: Bool {
        didSet {
            UserDefaults.standard.set(autoLockOnIdle, forKey: Self.autoLockOnIdleKey)
            applyAutoLockPolicy()
        }
    }
    @Published var autoLockIdleMinutes: Int {
        didSet {
            let value = max(1, autoLockIdleMinutes)
            if value != autoLockIdleMinutes {
                autoLockIdleMinutes = value
            }
            UserDefaults.standard.set(value, forKey: Self.autoLockIdleMinutesKey)
            applyAutoLockPolicy()
        }
    }
    @Published private(set) var operationAuditEvents: [OperationAuditEvent] = []
    @Published var backupDrillSession: BackupDrillSession?

    @Published private(set) var launchAtLoginFailure: String?

    private let core = CoreClient()
    private var deriveInFlight = false
    private static let pgpUserIDKey = "PasseportPGPUserID"
    private static let confirmEachOperationKey = "PasseportConfirmEachOperation"
    private static let requireTouchIDPerOperationKey = "PasseportRequireTouchIDPerOperation"
    private static let autoLockOnSleepKey = "PasseportAutoLockOnSleep"
    private static let autoLockOnIdleKey = "PasseportAutoLockOnIdle"
    private static let autoLockIdleMinutesKey = "PasseportAutoLockIdleMinutes"

    private let monitorState = AppModelMonitorState()
    private var autoLockTask: Task<Void, Never>?
    private var lastUserInput = Date()

    init() {
        let userID = AppModel.loadPGPUserID()
        pgpUserID = userID
        savedPGPUserID = userID
        hasSeed = SeedStore.seedExists()
        launchAtLogin = SMAppService.mainApp.status == .enabled
        confirmEachOperation = UserDefaults.standard.bool(forKey: Self.confirmEachOperationKey)
        requireTouchIDPerOperation = UserDefaults.standard.bool(forKey: Self.requireTouchIDPerOperationKey)
        autoLockOnSleep = UserDefaults.standard.bool(forKey: Self.autoLockOnSleepKey)
        autoLockOnIdle = UserDefaults.standard.bool(forKey: Self.autoLockOnIdleKey)
        let storedMinutes = UserDefaults.standard.integer(forKey: Self.autoLockIdleMinutesKey)
        autoLockIdleMinutes = storedMinutes > 0 ? storedMinutes : 10

        applyBridgePolicy()
        applySeedStoragePolicy()
        setupAutoLockMonitoring()
        startAutoLockTask()
        startOperationAuditObserver()
        Task {
            await self.refreshOperationAuditLog()
        }
    }

    deinit {
        let state = monitorState
        Task { @MainActor in
            state.clear()
        }
        autoLockTask?.cancel()
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

    private func applySeedStoragePolicy() {
        Task {
            do {
                try SeedStore.setSecureStorageEnabled(true)
                hasSeed = SeedStore.seedExists()
            } catch {
                status = error.localizedDescription
            }
        }
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
                launchAtLoginFailure = nil
            } else {
                if SMAppService.mainApp.status == .enabled {
                    try SMAppService.mainApp.unregister()
                }
                launchAtLoginFailure = nil
            }
        } catch {
            launchAtLoginFailure = error.localizedDescription
            status = "Could not update login item: \(error.localizedDescription)"
        }
    }

    func lock() {
        Task { @MainActor in
            await self.lockAsync()
        }
    }

    func lock(reason: String? = nil) {
        Task { @MainActor in
            await self.lockAsync(reason: reason)
        }
    }

    private func lockAsync(reason: String? = nil) async {
        self.identity = nil
        self.showingPrivateMaterial = false
        await SeedStore.clearCachedSeed()
        self.status = reason ?? "Locked"
    }

    /// Onboarding: mint a fresh random seed, derive its keys, and surface the
    /// recovery phrase so the user backs it up right away (wallet-style).
    func createNewIdentity() {
        runBusy("Creating a new identity") { [self] in
            if deriveInFlight {
                return
            }
            if identity != nil {
                status = "Keys already derived"
                return
            }
            deriveInFlight = true
            defer { deriveInFlight = false }
            if SeedStore.seedExists() {
                self.hasSeed = true
                status = "A seed already exists on this Mac — deriving keys."
                try await deriveFromCachedSeed()
                return
            }
            let seed = try await SeedStore.createRandomSeed()
            self.hasSeed = true
            self.identity = nil
            self.showingPrivateMaterial = false
            let phrase = try SeedBackup.recoveryPhrase(seed: seed)
            self.recoveryPhrase = phrase
            try await self.deriveFromCachedSeed()
            self.status = "New identity created — write down your recovery phrase"
        }
    }

    func deriveKeys() {
        runBusy("Deriving keys") { [self] in
            if identity != nil {
                status = "Keys already derived"
                return
            }
            if deriveInFlight {
                status = "Derivation already running"
                return
            }
            deriveInFlight = true
            defer { deriveInFlight = false }
            try await self.deriveFromCachedSeed()
            self.status = "Keys derived from your seed"
        }
    }

    /// Unlock the seed (Touch ID once per session) and derive the identity.
    private func deriveFromCachedSeed() async throws {
        let prf = try await SeedStore.prf(salt: SeedStore.rootSalt)
        let userID = self.pgpUserID.trimmedNonEmpty(defaultValue: "Passeport <passeport@localhost>")
        self.identity = try await self.core.derive(
            prf: prf,
            userID: userID,
            sshComment: "passeport"
        )
        // The seed is unlocked anyway; refresh the public-card cache so gpg
        // lookups won't need Touch ID later.
        await ScdBridge.refreshPublicCardCache(prf: prf, userID: userID)
    }

    func resetSeed() {
        runBusy("Removing the seed") {
            try await SeedStore.deleteSeed()
            PublicCardCache.clear()
            await MainActor.run {
                self.hasSeed = false
                self.identity = nil
                self.showingPrivateMaterial = false
                self.backupDrillSession = nil
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
            let result: GnuPGConfigurator.Result = try await Task.detached(priority: .userInitiated) {
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
            // The restored seed may differ from the old one; a stale cache
            // would advertise the wrong keys until re-derivation.
            PublicCardCache.clear()
            try await SeedStore.restoreSeed(seed)
            self.hasSeed = true
            self.showingPrivateMaterial = false
            try await self.deriveFromCachedSeed()
            self.status = "Identity restored from your recovery phrase"
        }
    }

    func startBackupDrill() {
        runBusy("Starting backup drill") { [self] in
            let seed = try await SeedStore.revealSeed()
            let words = try SeedBackup.recoveryPhrase(seed: seed).split(separator: " ").map(String.init)
            guard words.count == 24 else {
                throw PasseportError.bridgeFailed("recovery phrase format is invalid")
            }
            var selected = Set<Int>()
            while selected.count < 4 {
                selected.insert(Int.random(in: 0..<24))
            }
            let challenge = selected.sorted()
            self.backupDrillSession = BackupDrillSession(
                wordIndices: challenge,
                expectedWords: challenge.map { words[$0].lowercased() }
            )
            self.status = "Verify 4 words from your recovery phrase"
        }
    }

    func submitBackupDrill(answers: [String]) {
        runBusy("Verifying recovery drill") { [self] in
            guard let session = backupDrillSession else { return }
            guard answers.count == session.expectedWords.count else {
                throw PasseportError.bridgeFailed("all challenge words must be answered")
            }
            for (offset, expected) in session.expectedWords.enumerated() {
                let answer = answers[offset].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if answer != expected {
                    self.backupDrillSession = session
                    throw PasseportError.bridgeFailed("Backup drill failed: word \(session.wordIndices[offset] + 1) is incorrect")
                }
            }
            self.backupDrillSession = nil
            self.status = "Backup drill passed — your stored phrase matches"
        }
    }

    func dismissBackupDrill() {
        backupDrillSession = nil
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
            let result: GitConfigurator.Result = try await Task.detached(priority: .userInitiated) {
                try GitConfigurator.configure(fingerprint: identity.pgp.fingerprint, gpgPath: gpgPath)
            }.value
            await MainActor.run {
                self.status = "git will now sign commits with \(result.signingKey.suffix(16))"
            }
        }
    }

    func refreshOperationAuditLog() async {
        operationAuditEvents = await OperationAuditLog.shared.events(limit: 200)
    }

    func clearOperationAuditLog() {
        runBusy("Clearing operation audit log") {
            await OperationAuditLog.shared.clear()
            await MainActor.run {
                self.operationAuditEvents.removeAll()
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

    private func startOperationAuditObserver() {
        monitorState.auditLogObserver = NotificationCenter.default.addObserver(
            forName: .passeportAuditLogDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task {
                await self?.refreshOperationAuditLog()
            }
        }
    }

    // MARK: - Auto-lock

    private func setupAutoLockMonitoring() {
        let workspaceCenter = NSWorkspace.shared.notificationCenter
        monitorState.workspaceObservers.removeAll()
        monitorState.distributedObservers.removeAll()
        let distributedCenter = DistributedNotificationCenter.default()
        monitorState.distributedObservers.append(
            distributedCenter.addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in
                    self?.maybeAutoLock(reason: "Auto-locked on screen lock")
                }
            }
        )
        monitorState.distributedObservers.append(
            distributedCenter.addObserver(forName: Notification.Name("com.apple.screenIsUnlocked"), object: nil, queue: .main) { _ in
                // No action on unlock; keep for symmetry if needed later
            }
        )
        monitorState.workspaceObservers.append(
            workspaceCenter.addObserver(forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in
                    self?.maybeAutoLock(reason: "Auto-locked on system sleep")
                }
            }
        )

        let matcher: NSEvent.EventTypeMask = [
            .leftMouseDown,
            .rightMouseDown,
            .keyDown,
            .keyUp,
            .mouseMoved,
            .scrollWheel,
            .flagsChanged,
        ]
        monitorState.localEventMonitor = NSEvent.addLocalMonitorForEvents(matching: matcher) { [weak self] event in
            Task { @MainActor in self?.recordUserActivity() }
            return event
        }
        monitorState.globalEventMonitor = NSEvent.addGlobalMonitorForEvents(matching: matcher) { [weak self] _ in
            Task { @MainActor in self?.recordUserActivity() }
        }
    }

    private func recordUserActivity() {
        lastUserInput = Date()
    }

    private func maybeAutoLock(reason: String) {
        guard autoLockOnSleep else { return }
        lock(reason: reason)
    }

    private func startAutoLockTask() {
        autoLockTask?.cancel()
        guard autoLockOnIdle else {
            return
        }
        autoLockTask = Task.detached { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 10 * 1_000_000_000)
                await MainActor.run {
                    let timeout = max(1, self.autoLockIdleMinutes) * 60
                    if Date().timeIntervalSince(self.lastUserInput) >= Double(timeout) {
                        self.lock(reason: "Auto-locked after \(self.autoLockIdleMinutes) minutes of inactivity")
                    }
                }
            }
        }
    }

    private func applyAutoLockPolicy() {
        startAutoLockTask()
    }

    private func runBusy(_ message: String, operation: @MainActor @escaping () async throws -> Void) {
        guard !isBusy else { return }
        isBusy = true
        status = message

        Task { @MainActor in
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

struct BackupDrillSession: Identifiable, Equatable {
    let id = UUID()
    let wordIndices: [Int]
    let expectedWords: [String]
}

private extension String {
    func trimmedNonEmpty(defaultValue: String) -> String {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? defaultValue : trimmed
    }
}
