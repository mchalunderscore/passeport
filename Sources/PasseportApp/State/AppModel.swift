import AppKit
import Foundation
import ServiceManagement

enum PasseportIntegration: String, CaseIterable, Identifiable, Sendable {
    case ssh = "SSH"
    case openpgpBundled = "OpenPGP (Bundled)"
    case openpgpScdaemon = "OpenPGP (Scdaemon)"
    case git = "Git signing"
    case age = "age"
    case minisign = "minisign"
    var id: String { rawValue }
}

struct AppIssue: Identifiable {
    let id = UUID()
    let summary: String
    let details: String
    let suggestion: String
}

struct UpdateNotice: Identifiable {
    let version: String
    let releaseURL: URL
    var id: String { version }
}

struct SemanticVersion: Comparable, Equatable {
    let major: Int
    let minor: Int
    let patch: Int

    init?(_ tag: String) {
        var value = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.first == "v" || value.first == "V" { value.removeFirst() }
        guard !value.hasPrefix("-") else { return nil }
        value = String(value.split(separator: "+", maxSplits: 1)[0])
        value = String(value.split(separator: "-", maxSplits: 1)[0])
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 3,
              let major = Int(components[0]), major >= 0,
              let minor = Int(components[1]), minor >= 0,
              let patch = Int(components[2]), patch >= 0 else { return nil }
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }
}

private struct GitHubRelease: Decodable {
    let tagName: String
    let htmlURL: URL

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case htmlURL = "html_url"
    }
}

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
    @Published private(set) var bridgeRunning = false
    @Published private(set) var sshAgentRunning = false
    @Published var backgroundLauncherInstalled = LaunchAgentInstaller.isInstalled
    @Published private(set) var hasLocalGnuPG = false
    @Published var recoveryPhrase: String?
    @Published private(set) var contractWarning: String?
    @Published private(set) var gnupgStubWarning: String?
    @Published var launchAtLogin: Bool {
        didSet { applyLaunchAtLogin() }
    }
    @Published var hideDockIcon: Bool {
        didSet {
            UserDefaults.standard.set(hideDockIcon, forKey: Self.hideDockIconKey)
            applyAppearancePolicy()
        }
    }
    @Published var confirmEachOperation: Bool {
        didSet {
            UserDefaults.standard.set(confirmEachOperation, forKey: Self.confirmEachOperationKey)
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
    @Published private(set) var auditLogWarning: String?
    @Published var backupDrillSession: BackupDrillSession?
    @Published var passphraseRequest: PassphraseRequest?
    @Published private(set) var passphraseProtected = SeedStore.passphraseEnabled()
    @Published private(set) var integrationHealth: [PasseportIntegration: IntegrationHealth] = [:]
    @Published private(set) var integrationsNeedingRepair: Set<PasseportIntegration> = []
    @Published var presentedIssue: AppIssue?
    @Published var updateNotice: UpdateNotice?
    @Published private(set) var restoreCompletedID: UUID?
    @Published var backupVerifiedAt: Date?
    @Published var backupReminderDays: Int {
        didSet { UserDefaults.standard.set(backupReminderDays, forKey: Self.backupReminderDaysKey) }
    }
    @Published var setupChecklistDismissed: Bool {
        didSet { UserDefaults.standard.set(setupChecklistDismissed, forKey: Self.setupChecklistDismissedKey) }
    }

    @Published private(set) var launchAtLoginFailure: String?

    private let core = CoreClient()
    /// Retry to run after a successful on-demand unlock (see `requestUnlock`).
    private var pendingUnlockRetry: ((AppModel) -> Void)?
    /// Deferred work scheduled by the current `runBusy` operation, run after
    /// `isBusy` clears so the follow-up's own `runBusy` isn't rejected.
    private var pendingFollowUp: (() -> Void)?
    private static let pgpUserIDKey = "PasseportPGPUserID"
    private static let hideDockIconKey = "PasseportHideDockIcon"
    private static let confirmEachOperationKey = "PasseportConfirmEachOperation"
    private static let autoLockOnSleepKey = "PasseportAutoLockOnSleep"
    private static let autoLockOnIdleKey = "PasseportAutoLockOnIdle"
    private static let autoLockIdleMinutesKey = "PasseportAutoLockIdleMinutes"
    private static let backupVerifiedAtKey = "PasseportBackupVerifiedAt"
    private static let backupReminderDaysKey = "PasseportBackupReminderDays"
    private static let setupChecklistDismissedKey = "PasseportSetupChecklistDismissed"
    private static let integrationsNeedingRepairKey = "PasseportIntegrationsNeedingRepair"
    private static let dismissedUpdateTagKey = "PasseportDismissedUpdateTag"

    private let monitorState = AppModelMonitorState()
    private var autoLockTask: Task<Void, Never>?
    private var lastUserInput = Date()

    init() {
        let userID = AppModel.loadPGPUserID()
        pgpUserID = userID
        savedPGPUserID = userID
        hasSeed = SeedStore.seedExists()
        launchAtLogin = SMAppService.mainApp.status == .enabled
        hideDockIcon = UserDefaults.standard.bool(forKey: Self.hideDockIconKey)
        confirmEachOperation = UserDefaults.standard.bool(forKey: Self.confirmEachOperationKey)
        autoLockOnSleep = UserDefaults.standard.bool(forKey: Self.autoLockOnSleepKey)
        autoLockOnIdle = UserDefaults.standard.bool(forKey: Self.autoLockOnIdleKey)
        let storedMinutes = UserDefaults.standard.integer(forKey: Self.autoLockIdleMinutesKey)
        autoLockIdleMinutes = storedMinutes > 0 ? storedMinutes : 10
        backupVerifiedAt = UserDefaults.standard.object(forKey: Self.backupVerifiedAtKey) as? Date
        let storedReminderDays = UserDefaults.standard.object(forKey: Self.backupReminderDaysKey) as? Int
        backupReminderDays = storedReminderDays ?? 90
        setupChecklistDismissed = UserDefaults.standard.bool(forKey: Self.setupChecklistDismissedKey)
        let storedRepairs = UserDefaults.standard.stringArray(forKey: Self.integrationsNeedingRepairKey) ?? []
        integrationsNeedingRepair = Set(storedRepairs.compactMap(PasseportIntegration.init(rawValue:)))
        if storedRepairs.contains("OpenPGP") {
            integrationsNeedingRepair.formUnion([.openpgpBundled, .openpgpScdaemon])
        }

        refreshLocalToolingAvailability()
        refreshIntegrationHealth()
        applyBridgePolicy()
        setupAutoLockMonitoring()
        startAutoLockTask()
        startOperationAuditObserver()
        applyAppearancePolicy()
        Task {
            await self.refreshOperationAuditLog()
        }
    }

    private func applyAppearancePolicy() {
        let policy: NSApplication.ActivationPolicy = hideDockIcon ? .accessory : .regular
        // Defer until AppKit has finished constructing the application during
        // launch. Subsequent settings changes are applied on the next run-loop
        // turn as well, avoiding activation-policy changes mid-view update.
        DispatchQueue.main.async {
            NSApplication.shared.setActivationPolicy(policy)
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

    private func refreshLocalToolingAvailability() {
        // Resolving the login-shell PATH spawns a shell (cached after the first
        // call), so do it off the main thread to keep launch responsive.
        Task { [weak self] in
            let gnupg = await Task.detached(priority: .utility) {
                ToolingInstaller.hasGnuPG
            }.value
            self?.hasLocalGnuPG = gnupg
        }
    }

    func refreshIntegrationHealth() {
        Task { [weak self] in
            let base = await Task.detached(priority: .utility) { Self.collectIntegrationHealth() }.value
            guard let self else { return }
            self.applyIntegrationHealth(base)
        }
    }

    private nonisolated static func collectIntegrationHealth() -> [PasseportIntegration: IntegrationHealth] {
        [
            .ssh: SSHConfigurator.health,
            .openpgpBundled: GnuFreeGPGConfigurator.health,
            .openpgpScdaemon: GnuPGConfigurator.health,
            .git: GitConfigurator.health,
            .age: AgeConfigurator.health,
            .minisign: MinisignConfigurator.health,
        ]
    }

    private func applyIntegrationHealth(_ base: [PasseportIntegration: IntegrationHealth]) {
        integrationHealth = base.mapValues { $0 }
        for integration in integrationsNeedingRepair where base[integration] != .notConfigured {
            integrationHealth[integration] = .broken("The identity changed after this integration was configured. Repair it to install the new public identity.")
        }
    }

    func testIntegration(_ integration: PasseportIntegration) {
        Task { [weak self] in
            let base = await Task.detached(priority: .userInitiated) { Self.collectIntegrationHealth() }.value
            guard let self else { return }
            self.applyIntegrationHealth(base)
            let health = self.integrationHealth[integration] ?? .notConfigured
            switch health {
            case .working:
                guard let identity = self.identity else {
                    self.presentIssue(summary: "Unlock before testing", details: "The live test performs a real private-key operation.", suggestion: "Unlock Passeport, then run Test again.")
                    return
                }
                self.runBusy("Testing \(integration.rawValue)") {
                    let result = try await Task.detached(priority: .userInitiated) {
                        try IntegrationTester.run(
                            integration,
                            identity: identity,
                            sshSocketPath: SSHAgentServer.socketURL.path
                        )
                    }.value
                    self.status = result
                }
            case .notConfigured:
                self.presentIssue(summary: "\(integration.rawValue) is not configured", details: "No Passeport-managed configuration was found.", suggestion: "Configure the integration first, then run the test again.")
            case .broken(let detail):
                self.presentIssue(summary: "\(integration.rawValue) needs repair", details: detail, suggestion: "Use Repair to recreate Passeport's managed files without replacing unrelated commands.")
            }
        }
    }

    func testPluggableGnuPG() {
        switch pluggableGnuPGHealth {
        case .working: testIntegration(.openpgpScdaemon)
        case .notConfigured: presentIssue(summary: "Pluggable Scdaemon is not configured", details: "No Passeport scdaemon-program entry was found.", suggestion: "Choose Configure to connect GnuPG to Passeport.")
        case .broken(let detail): presentIssue(summary: "Pluggable Scdaemon needs repair", details: detail, suggestion: "Choose Repair to recreate the managed wrapper and agent configuration.")
        }
    }

    var pluggableGnuPGHealth: IntegrationHealth {
        let base = GnuPGConfigurator.health
        if integrationsNeedingRepair.contains(.openpgpScdaemon), base != .notConfigured {
            return .broken("The identity changed after GnuPG was configured. Repair it to import the new public identity.")
        }
        return base
    }

    func removePluggableGnuPG() {
        runBusy("Removing Pluggable Scdaemon configuration") { [self] in
            try GnuPGConfigurator.remove()
            integrationsNeedingRepair.remove(.openpgpScdaemon)
            persistIntegrationsNeedingRepair()
            status = "Removed Passeport's Pluggable Scdaemon configuration"
        }
    }

    func removeIntegration(_ integration: PasseportIntegration) {
        runBusy("Removing \(integration.rawValue) configuration") { [self] in
            switch integration {
            case .ssh: try SSHConfigurator.remove()
            case .openpgpBundled: try GnuFreeGPGConfigurator.remove()
            case .openpgpScdaemon: try GnuPGConfigurator.remove()
            case .git: try GitConfigurator.remove()
            case .age: try AgeConfigurator.remove()
            case .minisign: try MinisignConfigurator.remove()
            }
            integrationsNeedingRepair.remove(integration)
            persistIntegrationsNeedingRepair()
            refreshIntegrationHealth()
            status = "Removed Passeport's \(integration.rawValue) configuration"
        }
    }

    func removeAllConfiguration() {
        runBusy("Removing Passeport configuration") { [self] in
            // Validate every known hard refusal before the first destructive
            // step. In particular, legacy Git state must not turn a requested
            // all-or-nothing cleanup into a predictable partial cleanup.
            try GitConfigurator.preflightRemoval()
            for integration in PasseportIntegration.allCases {
                switch integration {
                case .ssh: try SSHConfigurator.remove()
                case .openpgpBundled: try GnuFreeGPGConfigurator.remove()
                case .openpgpScdaemon: try GnuPGConfigurator.remove()
                case .git: try GitConfigurator.remove()
                case .age: try AgeConfigurator.remove()
                case .minisign: try MinisignConfigurator.remove()
                }
            }
            if LaunchAgentInstaller.isInstalled { try LaunchAgentInstaller.uninstall() }
            backgroundLauncherInstalled = false
            integrationsNeedingRepair.removeAll()
            persistIntegrationsNeedingRepair()
            refreshIntegrationHealth()
            status = "Removed Passeport-managed configuration; the seed was kept"
        }
    }

    func copyDiagnostics() {
        Task { [weak self] in
            let base = await Task.detached(priority: .utility) { Self.collectIntegrationHealth() }.value
            guard let self else { return }
            self.applyIntegrationHealth(base)
            let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "development"
            let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
            let commit = Bundle.main.infoDictionary?["PasseportGitCommit"] as? String ?? "unknown"
            let integrations = PasseportIntegration.allCases.map { "\($0.rawValue): \(self.integrationHealth[$0]?.title ?? "Unknown")" }.joined(separator: "\n")
            let text = """
            Passeport \(version) (\(build))
            Git commit: \(commit)
            macOS \(ProcessInfo.processInfo.operatingSystemVersionString)
            Seed present: \(self.hasSeed)
            Identity unlocked: \(self.identity != nil)
            Encrypted vault present: \(SeedStore.seedExists())
            Bridge running: \(self.bridgeRunning)
            SSH agent running: \(self.sshAgentRunning)
            \(integrations)
            """
            self.copy(text, label: "diagnostics (no keys or secrets included)")
        }
    }

    private func presentIssue(summary: String, details: String, suggestion: String) {
        presentedIssue = AppIssue(summary: summary, details: details, suggestion: suggestion)
        status = summary
    }

    func checkForUpdates(manual: Bool = false) {
        if manual { status = "Checking GitHub for updates" }
        Task { [weak self] in
            guard let self else { return }
            do {
                let endpoint = URL(string: "https://api.github.com/repos/mchalunderscore/passeport/releases/latest")!
                var request = URLRequest(url: endpoint)
                request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
                request.setValue("Passeport/\(self.installedVersion)", forHTTPHeaderField: "User-Agent")
                request.timeoutInterval = 12
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                    throw PasseportError.bridgeFailed("GitHub did not return a release")
                }
                let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
                guard let installed = SemanticVersion(self.installedVersion),
                      let latest = SemanticVersion(release.tagName) else {
                    throw PasseportError.bridgeFailed("GitHub returned a release tag that is not semantic versioning")
                }
                guard latest > installed else {
                    if manual { self.status = "Passeport \(self.installedVersion) is up to date" }
                    return
                }
                if !manual,
                   UserDefaults.standard.string(forKey: Self.dismissedUpdateTagKey) == release.tagName {
                    return
                }
                self.updateNotice = UpdateNotice(version: release.tagName, releaseURL: release.htmlURL)
                self.status = "Passeport \(release.tagName) is available"
            } catch {
                guard manual else { return }
                self.presentIssue(
                    summary: "Could not check for updates",
                    details: error.localizedDescription,
                    suggestion: "Check your internet connection or visit the project website."
                )
            }
        }
    }

    var installedVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"
    }

    var releaseCodename: String {
        Bundle.main.infoDictionary?["PasseportReleaseCodename"] as? String ?? "Mi Goreng"
    }

    func openUpdate(_ notice: UpdateNotice) {
        UserDefaults.standard.set(notice.version, forKey: Self.dismissedUpdateTagKey)
        updateNotice = nil
        NSWorkspace.shared.open(notice.releaseURL)
    }

    func dismissUpdate(_ notice: UpdateNotice) {
        UserDefaults.standard.set(notice.version, forKey: Self.dismissedUpdateTagKey)
        updateNotice = nil
        status = "Update postponed"
    }

    private func markIntegrationRepaired(_ integrations: PasseportIntegration...) {
        integrations.forEach { integrationsNeedingRepair.remove($0) }
        persistIntegrationsNeedingRepair()
    }

    private func persistIntegrationsNeedingRepair() {
        UserDefaults.standard.set(integrationsNeedingRepair.map(\.rawValue).sorted(), forKey: Self.integrationsNeedingRepairKey)
    }

    private func markInstalledIntegrationsForRepair() async {
        integrationsNeedingRepair.formUnion(await installedIntegrations())
        persistIntegrationsNeedingRepair()
    }

    private func installedIntegrations() async -> Set<PasseportIntegration> {
        let configured = await Task.detached(priority: .utility) { Self.collectIntegrationHealth() }.value
        var result = Set(configured.compactMap { $0.value == .notConfigured ? nil : $0.key })
        if GnuPGConfigurator.health != .notConfigured { result.insert(.openpgpScdaemon) }
        return result
    }

    private static func loadPGPUserID() -> String {
        let saved = UserDefaults.standard.string(forKey: pgpUserIDKey)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let saved, !saved.isEmpty {
            return saved
        }
        return defaultPGPUserID
    }

    nonisolated static func backupVerificationIsDue(
        verifiedAt: Date?,
        reminderDays: Int,
        now: Date = Date()
    ) -> Bool {
        guard reminderDays > 0 else { return false }
        guard let verifiedAt else { return true }
        return now.timeIntervalSince(verifiedAt) >= TimeInterval(reminderDays * 86_400)
    }

    var backupVerificationIsDue: Bool {
        Self.backupVerificationIsDue(verifiedAt: backupVerifiedAt, reminderDays: backupReminderDays)
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
        Task { await ScdBridge.shared.setPolicy(confirmEachOperation: confirm) }
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
        await SeedStore.clearCachedSeed()
        self.status = reason ?? "Locked"
    }

    /// Onboarding: mint a fresh random seed, derive its keys, and surface the
    /// recovery phrase so the user backs it up right away (wallet-style). An
    /// existing seed just derives; a fresh one first asks for an optional
    /// password.
    func createNewIdentity() {
        if identity != nil {
            status = "Keys already derived"
            return
        }
        if SeedStore.seedExists() {
            deriveKeys()
            return
        }
        passphraseRequest = PassphraseRequest(purpose: .create)
    }

    /// Load the seed vault, prompting only when it has a password.
    func deriveKeys() {
        if identity != nil {
            status = "Keys already derived"
            return
        }
        Task { @MainActor in
            if await SeedStore.needsPassphrase() {
                self.passphraseRequest = PassphraseRequest(purpose: .unlock)
            } else {
                self.runUnlock(passphrase: "")
            }
        }
    }

    private func runDerive(status message: String) {
        runBusy("Deriving keys") { [self] in
            if identity != nil { return }
            try await self.deriveFromCachedSeed()
            self.status = message
        }
    }

    /// The user submitted the optional vault-password prompt.
    func submitPassphrase(_ passphrase: String) {
        guard let request = passphraseRequest else { return }
        passphraseRequest = nil
        switch request.purpose {
        case .create: runCreate(passphrase: passphrase)
        case .unlock: runUnlock(passphrase: passphrase)
        }
    }

    func cancelPassphrase() {
        passphraseRequest = nil
        pendingUnlockRetry = nil
    }

    private func runCreate(passphrase: String) {
        runBusy("Creating a new identity") { [self] in
            let seed = try await SeedStore.createRandomSeed()
            self.identity = nil
            try await SeedStore.enablePassphrase(passphrase)
            self.hasSeed = true
            self.passphraseProtected = SeedStore.passphraseEnabled()
            let phrase = try SeedBackup.recoveryPhrase(seed: seed)
            self.recoveryPhrase = phrase
            self.backupVerifiedAt = nil
            self.setupChecklistDismissed = false
            UserDefaults.standard.removeObject(forKey: Self.backupVerifiedAtKey)
            try await self.deriveFromCachedSeed()
            await self.markInstalledIntegrationsForRepair()
            self.status = passphrase.isEmpty
                ? "New identity created — write down your recovery phrase"
                : "New identity created — write down your recovery phrase and remember your vault password"
        }
    }

    private func runUnlock(passphrase: String) {
        let retry = pendingUnlockRetry
        pendingUnlockRetry = nil
        runBusy("Unlocking identity") { [self] in
            try await SeedStore.unlock(passphrase: passphrase)
            if identity == nil {
                try await self.deriveFromCachedSeed()
            }
            self.status = "Identity unlocked"
            if let retry {
                self.pendingFollowUp = { [weak self] in
                    guard let self else { return }
                    retry(self)
                }
            }
        }
    }

    /// Present the standard unlock sheet, resuming `retry` once the
    /// password is accepted. This keeps password-gated actions
    /// (e.g. saving the revocation certificate) reachable even when the keys
    /// are already derived but the session material is locked.
    private func requestUnlock(retry: @escaping (AppModel) -> Void) {
        if !SeedStore.passphraseEnabled() {
            pendingUnlockRetry = retry
            runUnlock(passphrase: "")
            return
        }
        pendingUnlockRetry = retry
        passphraseRequest = PassphraseRequest(purpose: .unlock)
        status = "Enter your password to continue"
    }

    /// Unlock the encrypted seed vault and derive the identity.
    private func deriveFromCachedSeed() async throws {
        let prf = try await SeedStore.prf(salt: SeedStore.rootSalt)
        let userID = self.pgpUserID.trimmedNonEmpty(defaultValue: "Passeport <passeport@localhost>")
        self.identity = try await self.core.derive(
            prf: prf,
            userID: userID,
            sshComment: "passeport"
        )
        // The seed is unlocked anyway; refresh the public-card cache so gpg
        // lookups won't need to unlock the private vault later.
        await ScdBridge.refreshPublicCardCache(prf: prf, userID: userID)
        refreshGnuPGStubWarning()
    }

    /// Warn when gpg's card stubs reference an older Passeport identity —
    /// the exact mismatch that makes ssh/gpg silently fail after a seed
    /// reset or restore.
    private func refreshGnuPGStubWarning() {
        guard let fingerprint = identity?.pgp.fingerprint else { return }
        Task.detached(priority: .utility) {
            let stale = GnuPGConfigurator.hasStaleCardStubs(currentFingerprint: fingerprint)
            await MainActor.run {
                self.gnupgStubWarning = stale
                    ? "GnuPG references an older Passeport identity — run “Configure GnuPG” to update its key stubs."
                    : nil
            }
        }
    }

    func resetSeed() {
        runBusy("Removing the seed") {
            try await SeedStore.deleteSeed()
            PublicCardCache.clear()
            await self.markInstalledIntegrationsForRepair()
            await MainActor.run {
                self.hasSeed = false
                self.identity = nil
                self.backupDrillSession = nil
                self.passphraseProtected = SeedStore.passphraseEnabled()
                self.backupVerifiedAt = nil
                self.setupChecklistDismissed = false
                UserDefaults.standard.removeObject(forKey: Self.backupVerifiedAtKey)
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

    /// Start the native SSH agent if it isn't already running and publish
    /// its state. Every path that needs the agent goes through here.
    private func ensureSSHAgentRunning() async throws {
        if !(await SSHAgentServer.shared.isRunning) {
            try await SSHAgentServer.shared.start()
        }
        sshAgentRunning = true
    }

    /// Bring the sockets up on launch so gpg and ssh work whenever the app
    /// runs. Only binds sockets; no seed access until an operation arrives.
    func startBridgeIfNeeded() {
        Task { @MainActor in
            do {
                try await self.ensureSSHAgentRunning()
            } catch {
                self.status = error.localizedDescription
            }
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

    func toggleSSHAgent() {
        runBusy(sshAgentRunning ? "Stopping SSH agent" : "Starting SSH agent") { [self] in
            if await SSHAgentServer.shared.isRunning {
                await SSHAgentServer.shared.stop()
                self.sshAgentRunning = false
                self.status = "SSH agent stopped"
            } else {
                try await self.ensureSSHAgentRunning()
                self.status = "SSH agent running"
            }
        }
    }

    /// Install `age-plugin-passeport` and surface the age recipient. Requires
    /// the encryption key to be available (unlock the identity first).
    func configureAge(installStandardAlias: Bool = false) {
        guard let identity else {
            status = "Unlock your identity first, then set up age"
            return
        }
        let recipient = identity.age.recipient
        runBusy("Configuring age encryption") { [self] in
            // The plugin decrypts through the bridge, so make sure it is up.
            if !(await ScdBridge.shared.isRunning) {
                try await ScdBridge.shared.start()
                self.bridgeRunning = true
            }
            let helperPath = try CoreLocator.helperURL().path
            let socketPath = ScdBridge.socketURL.path
            let result: AgeConfigurator.Result = try await Task.detached(priority: .userInitiated) {
                try AgeConfigurator.configure(
                    recipient: recipient,
                    helperPath: helperPath,
                    socketPath: socketPath,
                    installStandardAlias: installStandardAlias
                )
            }.value
            self.markIntegrationRepaired(.age)
            self.status = "passeport-age ready — encrypt with `passeport-age -e -r \(result.recipient)`, decrypt with `passeport-age -d`; external age/rage can use `-i \(result.identityFilePath)`"
        }
    }

    /// Install the minisign signing shim and write the public-key file. Signing
    /// is seed-derived and routes through the bridge's approval policy; no
    /// external binary is needed — the installed `minisign` signs and verifies.
    func configureMinisign(installStandardAlias: Bool = false) {
        guard let identity else {
            status = "Unlock your identity first, then set up minisign signing"
            return
        }
        runBusy("Configuring minisign signing") { [self] in
            if !(await ScdBridge.shared.isRunning) {
                try await ScdBridge.shared.start()
                self.bridgeRunning = true
            }
            let helperPath = try CoreLocator.helperURL().path
            let socketPath = ScdBridge.socketURL.path
            let publicKeyFile = identity.minisign.publicKey
            let result: MinisignConfigurator.Result = try await Task.detached(priority: .userInitiated) {
                try MinisignConfigurator.configure(
                    publicKeyFile: publicKeyFile,
                    helperPath: helperPath,
                    socketPath: socketPath,
                    installStandardAlias: installStandardAlias
                )
            }.value
            self.markIntegrationRepaired(.minisign)
            self.status = "passeport-minisign ready — sign with `passeport-minisign -Sm <file>`, verify with `passeport-minisign -Vm <file> -p \(result.publicKeyPath)`"
        }
    }

    /// Configure GNU-free OpenPGP: install the self-contained gpg
    /// drop-in wrapper and point git commit/tag signing at it. Coexists with
    /// This path uses no GnuPG binary.
    func configureGnuFreeGPG(installStandardAlias: Bool = false) {
        guard let identity else {
            status = "Unlock your identity first, then set up GNU-free OpenPGP"
            return
        }
        runBusy("Configuring GNU-free OpenPGP") { [self] in
            if !(await ScdBridge.shared.isRunning) {
                try await ScdBridge.shared.start()
                self.bridgeRunning = true
            }
            let helperPath = try CoreLocator.helperURL().path
            let socketPath = ScdBridge.socketURL.path
            let publicKey = identity.pgp.publicKey
            let fingerprint = identity.pgp.fingerprint
            let result: GnuFreeGPGConfigurator.Result = try await Task.detached(priority: .userInitiated) {
                let configured = try GnuFreeGPGConfigurator.configure(
                    publicKeyArmored: publicKey,
                    helperPath: helperPath,
                    socketPath: socketPath,
                    installStandardAlias: installStandardAlias
                )
                // Point Git at the GNU-free wrapper.
                _ = try GitConfigurator.configure(
                    fingerprint: fingerprint,
                    gpgPath: configured.gpgProgramPath
                )
                return configured
            }.value
            self.markIntegrationRepaired(.openpgpBundled, .git)
            self.status =
                "GNU-free OpenPGP ready — git signs commits via \(result.gpgProgramPath), no GnuPG needed"
        }
    }

    /// Point ~/.ssh/config at the native agent (IdentityAgent), starting the
    /// agent first if needed.
    func configureSSH() {
        runBusy("Configuring SSH") { [self] in
            try await self.ensureSSHAgentRunning()
            let result = try SSHConfigurator.configure(socketPath: SSHAgentServer.socketURL.path)
            self.markIntegrationRepaired(.ssh)
            self.status = "SSH configured — ssh now uses the Passeport agent via \(result.configPath)"
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
            status = "Unlock your identity first, then configure GnuPG"
            return
        }
        guard ToolingInstaller.hasGnuPG else {
            status = "Provide `gpg` on PATH before configuring GnuPG."
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
            self.markIntegrationRepaired(.openpgpScdaemon)
            self.status = "GnuPG configured. For SSH: export SSH_AUTH_SOCK=\(result.sshAuthSock)"
            self.refreshGnuPGStubWarning()
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

    /// Restore an identity from its 24-word phrase with an optional vault password.
    func restore(fromPhrase phrase: String, passphrase: String) {
        runBusy("Restoring from recovery phrase") { [self] in
            let seed = try SeedBackup.seed(fromPhrase: phrase)
            let prf = try await SeedStore.previewPRF(seed: seed, passphrase: passphrase, salt: SeedStore.rootSalt)
            let userID = pgpUserID.trimmedNonEmpty(defaultValue: "Passeport <passeport@localhost>")
            let replacement = try await core.derive(prf: prf, userID: userID, sshComment: "passeport")
            let installed = await installedIntegrations()
            try await SeedStore.commitRestoredIdentity(seed: seed, passphrase: passphrase)
            PublicCardCache.clear()
            self.hasSeed = true
            self.identity = replacement
            self.passphraseProtected = !passphrase.isEmpty
            await ScdBridge.refreshPublicCardCache(prf: prf, userID: userID)
            self.backupVerifiedAt = nil
            self.setupChecklistDismissed = false
            UserDefaults.standard.removeObject(forKey: Self.backupVerifiedAtKey)
            integrationsNeedingRepair.formUnion(installed)
            persistIntegrationsNeedingRepair()
            restoreCompletedID = UUID()
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
            guard let validation = Self.validateBackupDrill(answers: answers, session: session) else {
                self.backupDrillSession = nil
                self.backupVerifiedAt = Date()
                UserDefaults.standard.set(self.backupVerifiedAt, forKey: Self.backupVerifiedAtKey)
                self.status = "Backup drill passed — your stored phrase matches"
                return
            }
            switch validation {
            case .wrongAnswerCount:
                throw PasseportError.bridgeFailed("all challenge words must be answered")
            case .incorrectWord(let position):
                self.backupDrillSession = session
                throw PasseportError.bridgeFailed("Backup drill failed: word \(position + 1) is incorrect")
            }
        }
    }

    enum BackupDrillFailure: Equatable {
        case wrongAnswerCount
        case incorrectWord(position: Int)
    }

    static func validateBackupDrill(
        answers: [String],
        session: BackupDrillSession
    ) -> BackupDrillFailure? {
        guard answers.count == session.expectedWords.count else { return .wrongAnswerCount }
        for (offset, expected) in session.expectedWords.enumerated() {
            let answer = answers[offset].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if answer != expected {
                return .incorrectWord(position: session.wordIndices[offset])
            }
        }
        return nil
    }

    func dismissBackupDrill() {
        backupDrillSession = nil
    }

    func saveRevocationCertificate() {
        runBusy("Preparing revocation certificate") { [self] in
            if !(await SeedStore.canDeriveSilently()) {
                self.requestUnlock { $0.saveRevocationCertificate() }
                return
            }
            let prf = try await SeedStore.prf(salt: SeedStore.rootSalt)
            let userID = self.pgpUserID.trimmedNonEmpty(defaultValue: "Passeport <passeport@localhost>")
            let cert = try SeedBackup.revocationCertificate(prf: prf, userID: userID)
            self.save(text: cert, suggestedName: "passeport-revocation.asc")
        }
    }

    func configureGitSigning() {
        guard let identity else {
            status = "Unlock your identity first, then set up git signing"
            return
        }
        guard ToolingInstaller.hasGnuPG else {
            status = "Provide `gpg` on PATH before configuring git signing."
            return
        }
        runBusy("Configuring git commit signing") {
            let gpgPath = try GnuPGConfigurator.gpgPath()
            let result: GitConfigurator.Result = try await Task.detached(priority: .userInitiated) {
                try GitConfigurator.configure(fingerprint: identity.pgp.fingerprint, gpgPath: gpgPath)
            }.value
            await MainActor.run {
                self.markIntegrationRepaired(.git)
                self.status = "git will now sign commits with \(result.signingKey.suffix(16))"
            }
        }
    }

    /// Configure git to sign with SSH (`gpg.format=ssh`), signed through the
    /// native agent. Starts the agent if needed so signing works right away.
    func configureGitSigningSSH() {
        guard let identity else {
            status = "Unlock your identity first, then set up git signing"
            return
        }
        let publicKey = identity.ssh.publicKey
        runBusy("Configuring git SSH signing") { [self] in
            try await self.ensureSSHAgentRunning()
            let socketPath = SSHAgentServer.socketURL.path
            let result: GitConfigurator.SSHSigningResult = try await Task.detached(priority: .userInitiated) {
                try GitConfigurator.configureSSHSigning(publicKey: publicKey, sshAuthSock: socketPath)
            }.value
            self.markIntegrationRepaired(.git)
            self.status = "git will sign commits with SSH via \(result.signingProgramPath) — no shell setup needed"
        }
    }

    func refreshOperationAuditLog() async {
        operationAuditEvents = await OperationAuditLog.shared.events(limit: 200)
        auditLogWarning = await OperationAuditLog.shared.persistenceWarning()
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
                refreshIntegrationHealth()
            } catch {
                status = error.localizedDescription
                presentedIssue = AppIssue(
                    summary: "The operation could not be completed",
                    details: error.localizedDescription,
                    suggestion: "Review the affected integration or identity state, then try again. Copy diagnostics from Settings if the problem continues."
                )
            }
            isBusy = false
            if let followUp = pendingFollowUp {
                pendingFollowUp = nil
                followUp()
            }
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
            presentedIssue = AppIssue(
                summary: "The export could not be saved",
                details: error.localizedDescription,
                suggestion: "Choose another writable destination and try again."
            )
        }
    }
}

struct BackupDrillSession: Identifiable, Equatable {
    let id = UUID()
    let wordIndices: [Int]
    let expectedWords: [String]
}

/// Drives the password-entry sheet. Creation treats an empty entry as no
/// password; unlock requires the configured vault password.
struct PassphraseRequest: Identifiable, Equatable {
    enum Purpose { case create, unlock }
    let id = UUID()
    let purpose: Purpose
}

extension String {
    func trimmedNonEmpty(defaultValue: String) -> String {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? defaultValue : trimmed
    }
}
