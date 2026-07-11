import SwiftUI

enum AppSection: String, CaseIterable, Identifiable {
    case keys = "Keys"
    case backup = "Backup & Recovery"
    case integrations = "Integrations"
    case settings = "Settings"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .keys: "key.fill"
        case .backup: "lifepreserver"
        case .integrations: "terminal"
        case .settings: "gearshape"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var app: AppModel
    @State private var section: AppSection = .keys
    @State private var showingRestore = false
    @State private var showingLaunchAtLoginFailure = false

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                SidebarHeader()
                List(AppSection.allCases, selection: $section) { item in
                    Label(item.rawValue, systemImage: item.icon)
                        .tag(item)
                        .accessibilityLabel(item.rawValue)
                }
                .listStyle(.sidebar)
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 230, max: 280)
        } detail: {
            VStack(spacing: 0) {
                if let warning = app.contractWarning {
                    ContractWarningBanner(message: warning)
                        .padding([.horizontal, .top], 20)
                }
                if let warning = app.gnupgStubWarning {
                    ContractWarningBanner(message: warning)
                        .padding([.horizontal, .top], 20)
                }
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                StatusBar()
            }
            .navigationTitle(section.rawValue)
        }
        .toolbar {
            if #available(macOS 26.0, *) {
                ToolbarItem(placement: .primaryAction) {
                    IdentityToolbarControl()
                        .padding(.trailing, 10)
                }
                .sharedBackgroundVisibility(.hidden)
            } else {
                ToolbarItem(placement: .primaryAction) {
                    IdentityToolbarControl()
                }
            }
        }
        .sheet(item: Binding(
            get: { app.recoveryPhrase.map(RecoveryPhrase.init) },
            set: { if $0 == nil { app.dismissRecoveryPhrase() } }
        )) { phrase in
            RecoveryPhraseSheet(phrase: phrase.words)
                .environmentObject(app)
        }
        .sheet(isPresented: $showingRestore) {
            RestoreSheet()
                .environmentObject(app)
        }
        .sheet(item: Binding(
            get: { app.backupDrillSession },
            set: { if $0 == nil { app.dismissBackupDrill() } }
        )) { session in
            BackupDrillSheet(session: session)
                .environmentObject(app)
        }
        .sheet(item: Binding(
            get: { app.passphraseRequest },
            set: { if $0 == nil { app.cancelPassphrase() } }
        )) { request in
            PassphraseSheet(request: request)
                .environmentObject(app)
        }
        .alert(item: $app.presentedIssue) { issue in
            Alert(
                title: Text(issue.summary),
                message: Text("\(issue.details)\n\n\(issue.suggestion)"),
                primaryButton: .default(Text("Copy Details")) {
                    app.copy("\(issue.summary)\n\(issue.details)\nSuggested action: \(issue.suggestion)", label: "error details")
                },
                secondaryButton: .cancel()
            )
        }
        .alert(item: $app.updateNotice) { notice in
            Alert(
                title: Text("Passeport \(notice.version) is available"),
                message: Text("You are using Passeport \(app.installedVersion) “\(app.releaseCodename)”. Open the GitHub release page to review and download the new version."),
                primaryButton: .default(Text("View Release")) { app.openUpdate(notice) },
                secondaryButton: .cancel(Text("Later")) { app.dismissUpdate(notice) }
            )
        }
        .alert("Could not update login item", isPresented: $showingLaunchAtLoginFailure) {
            Button("OK", role: .cancel) { showingLaunchAtLoginFailure = false }
        } message: {
            Text(app.launchAtLoginFailure ?? "Unknown error")
        }
        .onChange(of: app.launchAtLoginFailure) { _, newValue in
            showingLaunchAtLoginFailure = newValue != nil
        }
    }

    @ViewBuilder private var detail: some View {
        switch section {
        case .keys: KeysSection(section: $section, showingRestore: $showingRestore)
        case .backup: BackupSection(showingRestore: $showingRestore)
        case .integrations: IntegrationsSection()
        case .settings: SettingsSection()
        }
    }
}

private struct RecoveryPhrase: Identifiable {
    let words: String
    var id: String { words }
}

/// App wordmark shown at the top of the sidebar, using the bundled glyph.
private struct SidebarHeader: View {
    var body: some View {
        HStack(spacing: 9) {
            Image("PasseportLogo")
                .resizable()
                .renderingMode(.template)
                .scaledToFit()
                .frame(width: 19, height: 19)
                .foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 1) {
                Text("Passeport")
                    .font(.headline)
                Text("Phrase-derived identity")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        // Leading inset chosen to line the glyph up with the sidebar rows'
        // icons; top padding is honored here (unlike inside the List).
        .padding(.leading, 18)
        .padding(.trailing, 12)
        .padding(.top, 10)
        .padding(.bottom, 6)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Passeport, phrase-derived identity")
    }
}

// MARK: - Keys

private struct KeysSection: View {
    @EnvironmentObject private var app: AppModel
    @Binding var section: AppSection
    @Binding var showingRestore: Bool
    @State private var confirmingReset = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            if app.hasSeed && !app.setupChecklistDismissed {
                SetupChecklist(section: $section)
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 14) {
                    if app.hasSeed {
                        HStack {
                            secretStatus
                            Spacer()
                            Button(role: .destructive) {
                                confirmingReset = true
                            } label: {
                                Label("Reset", systemImage: "arrow.counterclockwise")
                            }
                            .disabled(app.isBusy)
                        }
                    } else {
                        onboarding
                    }
                    Divider()
                    VStack(alignment: .leading, spacing: 6) {
                        Text("OpenPGP user ID")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        HStack {
                            TextField("Name <email>", text: $app.pgpUserID)
                                .textFieldStyle(.roundedBorder)
                                .onSubmit { app.savePGPUserID() }
                            Button("Save") { app.savePGPUserID() }
                                .disabled(!app.pgpUserIDHasUnsavedChanges)
                        }
                    }
                }
                .padding(6)
            } label: {
                Label("Identity", systemImage: "person.text.rectangle")
            }
            .sheet(isPresented: $confirmingReset) {
                ResetSeedSheet()
                    .environmentObject(app)
            }

            if app.hasSeed {
                // KeyDetailView scrolls the key material (top-aligned) or shows a
                // compact unavailable state while keys are unavailable.
                if app.identity != nil {
                    KeyDetailView()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if app.isBusy {
                    HStack {
                        ProgressView()
                            .controlSize(.small)
                        Text("Unlocking identity…")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    GroupBox {
                        VStack(spacing: 12) {
                            Image(systemName: "lock.open.display")
                                .font(.system(size: 30))
                                .foregroundStyle(.secondary)
                            Text("Your identity is locked")
                                .font(.title3.weight(.semibold))
                            Text("Unlock your protected identity when you need to view, export, or configure its public keys.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                                .frame(maxWidth: 430)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 30)
                    }
                }
            } else if app.isBusy {
                HStack {
                    ProgressView()
                        .controlSize(.small)
                    Text("Creating a new identity…")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Spacer(minLength: 0)
            }
        }
        .padding(24)
        .frame(maxWidth: 980, maxHeight: .infinity, alignment: .topLeading)
        .frame(maxWidth: .infinity, alignment: .top)
    }

    @ViewBuilder private var secretStatus: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label("Seed present on this Mac", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
            if app.passphraseProtected {
                Label("Vault is password protected", systemImage: "key.horizontal.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var onboarding: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Set up your identity")
                .font(.subheadline.weight(.semibold))
            Text("Create a fresh random identity, or import an existing 24-word BIP39 recovery phrase — from another Mac, or a wallet-style backup.")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Button {
                    app.createNewIdentity()
                } label: {
                    Label("Create New Identity", systemImage: "sparkles")
                }
                .buttonStyle(.borderedProminent)
                .disabled(app.isBusy)

                Button {
                    showingRestore = true
                } label: {
                    Label("Import Recovery Phrase", systemImage: "arrow.down.doc")
                }
                .disabled(app.isBusy)
            }
        }
    }
}

private struct SetupChecklist: View {
    @EnvironmentObject private var app: AppModel
    @Binding var section: AppSection
    @AppStorage("PasseportApprovalPolicyReviewed") private var approvalReviewed = false
    @AppStorage("PasseportAutoLockPolicyReviewed") private var autoLockReviewed = false

    private var configured: Bool { app.integrationHealth.values.contains(.working) }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Text("Finish setting up Passeport")
                    .font(.headline)
                checklistRow("Recovery phrase verified", complete: app.backupVerifiedAt != nil) { section = .backup }
                checklistRow("Operation approval reviewed", complete: approvalReviewed) {
                    approvalReviewed = true
                    section = .settings
                }
                checklistRow("Auto-lock policy reviewed", complete: autoLockReviewed) {
                    autoLockReviewed = true
                    section = .settings
                }
                checklistRow("At least one integration configured", complete: configured) { section = .integrations }
                HStack {
                    Spacer()
                    Button("Dismiss") { app.setupChecklistDismissed = true }
                        .controlSize(.small)
                }
            }
            .padding(6)
        } label: {
            Label("Setup checklist", systemImage: "checklist")
        }
    }

    private func checklistRow(_ title: String, complete: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: complete ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(complete ? .green : .secondary)
                Text(title)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
        .accessibilityValue(complete ? "Complete" : "Incomplete")
        .accessibilityHint("Opens the relevant setup page")
    }
}

// MARK: - Backup

private struct BackupSection: View {
    @EnvironmentObject private var app: AppModel
    @Binding var showingRestore: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("Your identity is a 24-word recovery phrase. The seed is stored only on this Mac — write the phrase down to recover it, or to set the same identity up on another Mac.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        if let verified = app.backupVerifiedAt, !app.backupVerificationIsDue {
                            Label("Recovery phrase verified \(verified.formatted(date: .abbreviated, time: .shortened))", systemImage: "checkmark.shield.fill")
                                .foregroundStyle(.green)
                        } else if let verified = app.backupVerifiedAt {
                            Label("Recovery phrase verification is due — last checked \(verified.formatted(date: .abbreviated, time: .omitted))", systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        } else {
                            Label("Recovery phrase has not been verified", systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }

                        HStack {
                            Button {
                                app.revealRecoveryPhrase()
                            } label: {
                                Label("Show Recovery Phrase", systemImage: "list.number")
                            }
                            .disabled(app.isBusy || !app.hasSeed)

                            Button {
                                app.startBackupDrill()
                            } label: {
                                Label("Verify Recovery Phrase", systemImage: "checkmark.shield")
                            }
                            .disabled(app.isBusy || !app.hasSeed)

                            Button {
                                showingRestore = true
                            } label: {
                                Label("Restore…", systemImage: "arrow.uturn.backward")
                            }
                            .disabled(app.isBusy)
                        }
                    }
                    .padding(6)
                } label: {
                    Label("Backup & Recovery", systemImage: "lifepreserver")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("A revocation certificate lets you publicly retire the key if the seed is ever lost or compromised. Save it now and keep it with your backups.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        Button {
                            app.saveRevocationCertificate()
                        } label: {
                            Label("Save Revocation Certificate", systemImage: "xmark.seal")
                        }
                        .disabled(app.isBusy || !app.hasSeed)
                    }
                    .padding(6)
                } label: {
                    Label("Revocation Certificate", systemImage: "xmark.seal")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("If your recovery phrase or seed may have been exposed, create a replacement identity rather than continuing to use it.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Text("1. Save and publish the old OpenPGP revocation certificate where appropriate.\n2. Record which services use each old public key.\n3. Remove the old seed only after the replacement phrase is written down and verified.\n4. Repair each integration and replace registered public keys on remote services.")
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                } label: {
                    Label("Replace a Compromised Identity", systemImage: "arrow.triangle.2.circlepath")
                }
                Spacer(minLength: 0)
            }
            .padding(24)
            .frame(maxWidth: 980, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
    }
}

// MARK: - Integrations

private enum OpenPGPBackend: String, CaseIterable, Identifiable {
    case bundled = "GNU-free (Bundled)"
    case scdaemon = "Pluggable Scdaemon"
    var id: String { rawValue }
}

private enum GitSigningMethod: String, CaseIterable, Identifiable {
    case ssh = "SSH-based"
    case pgp = "PGP-based"
    var id: String { rawValue }
}

private struct IntegrationsSection: View {
    @EnvironmentObject private var app: AppModel
    @AppStorage("PasseportOpenPGPBackend") private var openpgpBackend: OpenPGPBackend = .bundled
    @AppStorage("PasseportGitSigningMethod") private var gitMethod: GitSigningMethod = .ssh
    @AppStorage("PasseportInstallStandardGPGAlias") private var installStandardGPGAlias = false
    @AppStorage("PasseportInstallStandardAgeAlias") private var installStandardAgeAlias = false
    @AppStorage("PasseportInstallStandardMinisignAlias") private var installStandardMinisignAlias = false

    private var hasIdentity: Bool { app.identity != nil }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                statusHeader
                sectionHeader("Identity services", description: "Make your keys available to command-line tools and applications.")
                sshCard
                openpgpCard
                sectionHeader("App integrations", description: "Configure tools to sign or encrypt with your Passeport identity.")
                gitCard
                ageCard
                minisignCard
                Spacer(minLength: 0)
            }
            .padding(24)
            .frame(maxWidth: 980, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
    }

    // MARK: - Status header

    private var statusHeader: some View {
        GroupBox {
            VStack(spacing: 12) {
                HStack(spacing: 10) {
                    Image(systemName: hasIdentity ? "checkmark.seal.fill" : "lock")
                        .font(.title3)
                        .foregroundStyle(hasIdentity ? .green : .secondary)
                        .frame(width: 24)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(hasIdentity ? "Identity ready" : "Identity locked")
                            .font(.headline)
                        Text(identitySummary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer(minLength: 12)
                }
                Divider()
                serviceRow("SSH Agent", description: "Serves your authentication key to SSH clients", running: app.sshAgentRunning) { app.toggleSSHAgent() }
                Divider()
                serviceRow("GnuPG Bridge", description: "Connects GnuPG to your Passeport identity", running: app.bridgeRunning) { app.toggleBridge() }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        } label: {
            Label("Identity & Services", systemImage: "person.text.rectangle")
        }
    }

    private var identitySummary: String {
        app.identity?.pgp.fingerprint.uppercased() ?? "Unlock your identity above to configure integrations."
    }

    private func serviceRow(_ title: String, description: String, running: Bool, toggle: @escaping () -> Void) -> some View {
        HStack(spacing: 10) {
            Circle()
                .fill(running ? Color.green : Color.secondary.opacity(0.35))
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(running ? "Running" : "Stopped")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button(running ? "Stop" : "Start", action: toggle)
                .controlSize(.small)
                .frame(minWidth: 52)
        }
        .disabled(app.isBusy)
    }

    private func sectionHeader(_ title: String, description: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.title3.weight(.semibold))
            Text(description)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 4)
    }

    private func integrationCard<Actions: View, Detail: View>(
        icon: String,
        title: String,
        subtitle: String,
        disabledReason: String? = nil,
        @ViewBuilder actions: () -> Actions,
        @ViewBuilder detail: () -> Detail
    ) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: icon)
                        .font(.title3)
                        .foregroundStyle(.secondary)
                        .frame(width: 26, height: 26)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title)
                            .font(.headline)
                        Text(subtitle)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 12)
                    actions()
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) { detail() }
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                if let disabledReason {
                    Label(disabledReason, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(6)
        }
    }

    private func pathDetail(value: String, copyLabel: String) -> some View {
        HStack(spacing: 10) {
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
            Button {
                app.copy(value, label: copyLabel)
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .controlSize(.small)
        }
    }

    @ViewBuilder
    private func healthControls(_ integration: PasseportIntegration, repair: @escaping () -> Void) -> some View {
        let health = app.integrationHealth[integration] ?? .notConfigured
        HStack(spacing: 10) {
            Label(health.title, systemImage: health == .working ? "checkmark.circle.fill" : (health == .notConfigured ? "circle" : "exclamationmark.triangle.fill"))
                .foregroundStyle(health == .working ? .green : (health == .notConfigured ? .secondary : .orange))
                .font(.caption)
            Spacer()
            Button("Test") { app.testIntegration(integration) }
                .controlSize(.small)
                .accessibilityLabel("Test \(integration.rawValue) integration")
                .accessibilityHint("Performs a real private-key operation and verifies its result")
            if health != .notConfigured {
                Button("Repair", action: repair)
                    .controlSize(.small)
                    .accessibilityLabel("Repair \(integration.rawValue) integration")
                Button("Remove", role: .destructive) { app.removeIntegration(integration) }
                    .controlSize(.small)
                    .accessibilityLabel("Remove \(integration.rawValue) integration")
            }
        }
        if case .broken(let reason) = health {
            Text(reason).font(.caption).foregroundStyle(.orange)
        }
    }

    // MARK: - Cards

    private var sshCard: some View {
        integrationCard(
            icon: "terminal",
            title: "SSH",
            subtitle: "Authenticate with your Passeport key through the built-in SSH agent.",
            actions: {
                Button {
                    if let key = app.identity?.ssh.publicKey {
                        app.copy(key, label: "SSH public key")
                    }
                } label: {
                    Label("Copy Key", systemImage: "doc.on.doc")
                }
                .controlSize(.small)
                .disabled(!hasIdentity)
                Button("Configure") { app.configureSSH() }
                    .controlSize(.small)
                    .disabled(app.isBusy)
            },
            detail: {
                Text("Passeport serves the authentication subkey directly, with no GnuPG dependency. Each signature follows your approval settings.")
                Label("Configure updates ~/.ssh/config to use the Passeport agent.", systemImage: "info.circle")
                    .font(.caption)
                healthControls(.ssh) { app.configureSSH() }
            }
        )
    }

    private var openpgpCard: some View {
        let needsGnuPG = openpgpBackend == .scdaemon
        let enabled = !app.isBusy && hasIdentity && (!needsGnuPG || app.hasLocalGnuPG)
        let configureExplanation = switch openpgpBackend {
        case .bundled:
            "Configure installs `passeport-gpg` in Application Support and ~/.local/bin, then points Git signing at it. The optional `gpg` alias never replaces a command Passeport does not own."
        case .scdaemon:
            "Configure updates ~/.gnupg/gpg-agent.conf, imports the public key, and connects your existing GnuPG agent to Passeport."
        }
        return integrationCard(
            icon: "key",
            title: "OpenPGP",
            subtitle: "Sign and decrypt with a bundled GNU-free tool or your existing GnuPG installation.",
            disabledReason: hasIdentity && needsGnuPG && !app.hasLocalGnuPG
                ? "Pluggable Scdaemon requires a system `gpg` on PATH. Install GnuPG or choose GNU-free (Bundled)."
                : nil,
            actions: {
                Button("Configure") {
                    switch openpgpBackend {
                    case .bundled: app.configureGnuFreeGPG(installStandardAlias: installStandardGPGAlias)
                    case .scdaemon: app.configureGnuPG()
                    }
                }
                .controlSize(.small)
                .disabled(!enabled)
            },
            detail: {
                Picker("Backend", selection: $openpgpBackend) {
                    ForEach(OpenPGPBackend.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .frame(maxWidth: 390, alignment: .leading)
                Text("GNU-free installs Passeport's self-contained gpg-compatible command. Pluggable Scdaemon exposes the identity to your existing gpg-agent as a virtual smartcard.")
                if openpgpBackend == .bundled {
                    Toggle("Also install as `gpg`", isOn: $installStandardGPGAlias)
                        .toggleStyle(.checkbox)
                }
                Label(configureExplanation, systemImage: "info.circle")
                    .font(.caption)
                if openpgpBackend == .bundled {
                    healthControls(.openpgpBundled) { app.configureGnuFreeGPG(installStandardAlias: installStandardGPGAlias) }
                } else {
                    let health = app.pluggableGnuPGHealth
                    HStack {
                        Label(health.title, systemImage: health == .working ? "checkmark.circle.fill" : (health == .notConfigured ? "circle" : "exclamationmark.triangle.fill"))
                            .font(.caption)
                            .foregroundStyle(health == .working ? .green : (health == .notConfigured ? .secondary : .orange))
                        Spacer()
                        Button("Test") { app.testPluggableGnuPG() }.controlSize(.small)
                        if health != .notConfigured {
                            Button("Repair") { app.configureGnuPG() }.controlSize(.small)
                            Button("Remove", role: .destructive) { app.removePluggableGnuPG() }.controlSize(.small)
                        }
                    }
                }
            }
        )
    }

    private var gitCard: some View {
        let needsGnuPG = gitMethod == .pgp && openpgpBackend == .scdaemon
        let enabled = !app.isBusy && hasIdentity && (!needsGnuPG || app.hasLocalGnuPG)
        let configureExplanation = switch gitMethod {
        case .ssh:
            "Configure writes Passeport's signing key and allowed-signers files under ~/.ssh, then updates your global Git signing settings."
        case .pgp:
            "Configure updates your global Git signing settings to use the OpenPGP backend selected above."
        }
        return integrationCard(
            icon: "checkmark.seal",
            title: "Git commit signing",
            subtitle: "Sign commits and tags so hosting services can display them as verified.",
            disabledReason: hasIdentity && needsGnuPG && !app.hasLocalGnuPG
                ? "PGP signing through Pluggable Scdaemon requires a system `gpg` on PATH. Install GnuPG or choose GNU-free (Bundled) above."
                : nil,
            actions: {
                Button("Configure") {
                    switch gitMethod {
                    case .ssh: app.configureGitSigningSSH()
                    case .pgp:
                        switch openpgpBackend {
                        case .bundled: app.configureGnuFreeGPG(installStandardAlias: installStandardGPGAlias)
                        case .scdaemon: app.configureGitSigning()
                        }
                    }
                }
                .controlSize(.small)
                .disabled(!enabled)
            },
            detail: {
                Picker("Signing method", selection: $gitMethod) {
                    ForEach(GitSigningMethod.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .frame(maxWidth: 330, alignment: .leading)
                Text("SSH-based signing uses the native agent. PGP-based signing follows the OpenPGP backend selected above.")
                Label(configureExplanation, systemImage: "info.circle")
                    .font(.caption)
                healthControls(.git) {
                    if gitMethod == .ssh { app.configureGitSigningSSH() }
                    else if openpgpBackend == .bundled { app.configureGnuFreeGPG(installStandardAlias: installStandardGPGAlias) }
                    else { app.configureGitSigning() }
                }
            }
        )
    }

    private var ageCard: some View {
        integrationCard(
            icon: "lock.doc",
            title: "File encryption",
            subtitle: "Encrypt standard age files to your Passeport recipient and decrypt them with approval.",
            actions: {
                Button("Configure") { app.configureAge(installStandardAlias: installStandardAgeAlias) }
                    .controlSize(.small)
                    .disabled(app.isBusy || !hasIdentity)
            },
            detail: {
                Text("Passeport's age command handles decryption through the app. External age and rage tools can encrypt to the same recipient.")
                Toggle("Also install as `age`", isOn: $installStandardAgeAlias)
                    .toggleStyle(.checkbox)
                Label("Configure installs `passeport-age` and the plugin in Application Support, links them into ~/.local/bin, and writes the public plugin identity file. The optional `age` alias never replaces a command Passeport does not own.", systemImage: "info.circle")
                    .font(.caption)
                if let recipient = app.identity?.age.recipient {
                    pathDetail(value: recipient, copyLabel: "age recipient")
                }
                healthControls(.age) { app.configureAge(installStandardAlias: installStandardAgeAlias) }
            }
        )
    }

    private var minisignCard: some View {
        integrationCard(
            icon: "signature",
            title: "File signing",
            subtitle: "Sign and verify files with minisign, without depending on GnuPG.",
            actions: {
                Button("Configure") { app.configureMinisign(installStandardAlias: installStandardMinisignAlias) }
                    .controlSize(.small)
                    .disabled(app.isBusy || !hasIdentity)
            },
            detail: {
                Text("Signatures require approval through Passeport. Anyone can verify them with the standard minisign command and your public key.")
                Toggle("Also install as `minisign`", isOn: $installStandardMinisignAlias)
                    .toggleStyle(.checkbox)
                Label("Configure installs `passeport-minisign` in Application Support and ~/.local/bin, and writes the public key to ~/.minisign/passeport.pub. The optional `minisign` alias never replaces a command Passeport does not own.", systemImage: "info.circle")
                    .font(.caption)
                if let publicKey = app.identity?.minisign.publicKey {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Public key")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(publicKey)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.primary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(9)
                            .background(.quaternary.opacity(0.35))
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
                healthControls(.minisign) { app.configureMinisign(installStandardAlias: installStandardMinisignAlias) }
            }
        )
    }

}

// MARK: - Settings

struct SettingsSection: View {
    @EnvironmentObject private var app: AppModel
    @State private var confirmingClearLog = false
    @State private var confirmingCleanup = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                settingsCard("Appearance", systemImage: "menubar.rectangle") {
                    Toggle("Hide Passeport from the Dock", isOn: $app.hideDockIcon)
                    Text("Passeport remains available from the menu bar. Use Open Passeport there whenever you need the main window.")
                        .settingsHelp()
                }

                settingsCard("Availability", systemImage: "power") {
                    Toggle("Start bridge at login", isOn: $app.launchAtLogin)
                    Toggle("Start Passeport on demand", isOn: Binding(
                        get: { app.backgroundLauncherInstalled },
                        set: { _ in app.toggleBackgroundLauncher() }
                    ))
                    .disabled(app.isBusy)
                    Text("The background launcher opens Passeport when another app requests one of your keys.")
                        .settingsHelp()
                }

                settingsCard("Operation approval", systemImage: "checkmark.shield") {
                    Toggle("Confirm each signature or decryption", isOn: $app.confirmEachOperation)
                    Text("Confirmation shows what is being signed before each operation, protecting against a compromised client using the key silently.")
                        .settingsHelp()
                }

                settingsCard("Auto-lock", systemImage: "lock") {
                    Toggle("Auto-lock when screen locks or sleeps", isOn: $app.autoLockOnSleep)
                    Toggle("Auto-lock after inactivity", isOn: $app.autoLockOnIdle)
                    Picker("Idle timeout", selection: $app.autoLockIdleMinutes) {
                        Text("1 minute").tag(1)
                        Text("2 minutes").tag(2)
                        Text("5 minutes").tag(5)
                        Text("10 minutes").tag(10)
                        Text("15 minutes").tag(15)
                        Text("30 minutes").tag(30)
                        Text("60 minutes").tag(60)
                    }
                    .pickerStyle(.menu)
                    .disabled(!app.autoLockOnIdle)
                }

                settingsCard("Recovery verification", systemImage: "checkmark.shield") {
                    Picker("Remind me to verify", selection: $app.backupReminderDays) {
                        Text("Every 30 days").tag(30)
                        Text("Every 90 days").tag(90)
                        Text("Every 180 days").tag(180)
                        Text("Never").tag(0)
                    }
                    .pickerStyle(.menu)
                    Text("When due, Passeport marks the backup on the Backup & Recovery page. Verification checks four randomly selected words without displaying or copying the full phrase.")
                        .settingsHelp()
                }

                settingsCard("Operation audit log", systemImage: "list.bullet.rectangle") {
                    if let warning = app.auditLogWarning {
                        Label(warning, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.caption)
                    }
                    if app.operationAuditEvents.isEmpty {
                        ContentUnavailableView(
                            "No Recorded Operations",
                            systemImage: "checkmark.shield",
                            description: Text("Approved and denied operations will appear here.")
                        )
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                    } else {
                        ForEach(app.operationAuditEvents) { event in
                            OperationAuditRow(event: event)
                            if event.id != app.operationAuditEvents.last?.id { Divider() }
                        }
                    }
                    HStack {
                        Button("Refresh") { Task { await app.refreshOperationAuditLog() } }
                        Spacer()
                        Button("Clear Log", role: .destructive) { confirmingClearLog = true }
                            .disabled(app.operationAuditEvents.isEmpty)
                    }
                    .confirmationDialog("Clear the operation audit log?", isPresented: $confirmingClearLog) {
                        Button("Clear Log", role: .destructive) { app.clearOperationAuditLog() }
                    } message: {
                        Text("This removes Passeport's local record of approved and denied operations.")
                    }
                }

                settingsCard("Diagnostics & cleanup", systemImage: "wrench.and.screwdriver") {
                    Button("Copy Diagnostics") { app.copyDiagnostics() }
                    Text("Diagnostics include app and integration state, but never keys, recovery words, passwords, or operation contents.")
                        .settingsHelp()
                    Divider()
                    Button("Remove Passeport Configuration…", role: .destructive) { confirmingCleanup = true }
                    Text("Removes Passeport-owned command links, SSH and Git configuration, public integration files, and the background launcher. Your identity vault remains on disk.")
                        .settingsHelp()
                    .confirmationDialog("Remove Passeport-managed configuration?", isPresented: $confirmingCleanup) {
                        Button("Remove Configuration", role: .destructive) { app.removeAllConfiguration() }
                    } message: {
                        Text("The identity seed is not deleted. Files and settings not owned by Passeport are left alone.")
                    }
                }

                settingsCard("About Passeport", systemImage: "info.circle") {
                    HStack {
                        Text("Passeport \(app.installedVersion) “\(app.releaseCodename)”")
                        Spacer()
                        Link(destination: URL(string: "https://mchalunderscore.github.io/passeport/")!) {
                            Label("Open Website", systemImage: "globe")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    Text("The passport logo is from Solar Bold Icons and is licensed under CC Attribution.")
                        .settingsHelp()
                    Button("Check for Updates") { app.checkForUpdates(manual: true) }
                        .disabled(app.isBusy)
                }
            }
            .padding(24)
            .frame(maxWidth: 760, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
    }

    private func settingsCard<Content: View>(
        _ title: String,
        systemImage: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) { content() }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
        } label: {
            Label(title, systemImage: systemImage)
        }
    }
}

private extension View {
    func settingsHelp() -> some View {
        font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct OperationAuditRow: View {
    let event: OperationAuditEvent
    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(event.kind)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
                Text(event.outcome.uppercased())
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Text("\(Self.timestampFormatter.string(from: event.timestamp)) · \(event.requestingClient)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("\(event.summary)\(event.byteCount > 0 ? " · \(event.byteCount) bytes" : "")")
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            if !event.details.isEmpty {
                Text(event.details)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Shared

/// Explains why key-dependent actions are disabled until an identity exists.
private struct RequiresKeysHint: View {
    var body: some View {
        Label("Unlock your identity to enable this.", systemImage: "info.circle")
            .font(.caption)
            .foregroundStyle(.secondary)
    }
}

private struct ContractWarningBanner: View {
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(message)
                .font(.caption)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.15))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Warning: \(message)")
    }
}

private struct IdentityToolbarControl: View {
    @EnvironmentObject private var app: AppModel

    @ViewBuilder
    var body: some View {
        if app.hasSeed {
            let isLocked = app.identity == nil
            identityButton(isLocked: isLocked)
        }
    }

    @ViewBuilder
    private func identityButton(isLocked: Bool) -> some View {
        if #available(macOS 26.0, *) {
            if isLocked {
                Button {
                    app.deriveKeys()
                } label: {
                    toolbarLabel(title: "Unlock", systemImage: "lock.open")
                }
                .buttonStyle(.glassProminent)
                .buttonBorderShape(.capsule)
                .controlSize(.small)
                .disabled(app.isBusy)
                .help("Unlock identity")
                .accessibilityLabel("Unlock identity")
            } else {
                Button {
                    app.lock()
                } label: {
                    toolbarLabel(title: "Lock", systemImage: "lock")
                }
                .buttonStyle(.glass)
                .buttonBorderShape(.capsule)
                .controlSize(.small)
                .disabled(app.isBusy)
                .help("Lock identity")
                .accessibilityLabel("Lock identity")
            }
        } else if isLocked {
            Button {
                app.deriveKeys()
            } label: {
                toolbarLabel(title: "Unlock", systemImage: "lock.open")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .disabled(app.isBusy)
            .help("Unlock identity")
            .accessibilityLabel("Unlock identity")
        } else {
            Button {
                app.lock()
            } label: {
                toolbarLabel(title: "Lock", systemImage: "lock")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(app.isBusy)
            .help("Lock identity")
            .accessibilityLabel("Lock identity")
        }
    }

    private func toolbarLabel(title: String, systemImage: String) -> some View {
        HStack(spacing: 5) {
            Image(systemName: systemImage)
            Text(title)
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 3)
        .fixedSize()
    }
}

private struct StatusBar: View {
    @EnvironmentObject private var app: AppModel

    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 7) {
                if app.isBusy {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Image(systemName: statusIcon)
                        .foregroundStyle(statusColor)
                }
                Text(app.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16)
            .frame(height: 34)
            .background(.bar)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Status: \(app.status)")
        }
    }

    private var statusIcon: String {
        let value = app.status.lowercased()
        if value.contains("failed") || value.contains("error") || value.contains("could not") {
            return "exclamationmark.triangle"
        }
        if value.contains("denied") || value.contains("cancelled") {
            return "xmark.circle"
        }
        if app.identity == nil || value.contains("locked") {
            return "lock"
        }
        return "info.circle"
    }

    private var statusColor: Color {
        let value = app.status.lowercased()
        if value.contains("failed") || value.contains("error") || value.contains("could not") {
            return .orange
        }
        if value.contains("denied") || value.contains("cancelled") {
            return .red
        }
        return .secondary
    }
}

/// A BIP39 phrase laid out in the standard 4 columns of 6 (words 1–6, 7–12,
/// 13–18, 19–24), column by column. `cell` renders one numbered slot.
private struct MnemonicColumns<Cell: View>: View {
    let spacing: CGFloat
    var columnSpacing: CGFloat = 18
    var labelWidth: CGFloat = 22
    @ViewBuilder let cell: (Int) -> Cell

    var body: some View {
        HStack(alignment: .top, spacing: columnSpacing) {
            ForEach(0..<4, id: \.self) { column in
                VStack(alignment: .leading, spacing: spacing) {
                    ForEach(0..<6, id: \.self) { row in
                        let index = column * 6 + row
                        HStack(spacing: 6) {
                            Text("\(index + 1).")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                                .frame(width: labelWidth, alignment: .trailing)
                            cell(index)
                        }
                    }
                }
            }
        }
    }
}

private struct RecoveryPhraseSheet: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.dismiss) private var dismiss
    let phrase: String

    private var words: [String] { phrase.split(separator: " ").map(String.init) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Recovery Phrase")
                .font(.title3.weight(.semibold))
            Text("Write these 24 words down in order and store them offline. Anyone with them can reconstruct your entire identity.")
                .font(.callout)
                .foregroundStyle(.secondary)

            MnemonicColumns(spacing: 8) { index in
                Text(index < words.count ? words[index] : "")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(minWidth: 84, alignment: .leading)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.35))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            HStack {
                Text("For safety, Passeport does not place recovery phrases on the clipboard.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(28)
        // Wide enough for the 4 mnemonic columns (~530pt) plus padding.
        .frame(width: 620)
    }
}

private struct PassphraseSheet: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.dismiss) private var dismiss
    let request: PassphraseRequest

    @State private var passphrase = ""
    @State private var confirmation = ""
    @FocusState private var focused: Bool

    private var isUnlock: Bool { request.purpose == .unlock }

    private var title: String {
        switch request.purpose {
        case .create: "Protect with a password?"
        case .unlock: "Enter your password"
        }
    }

    private var explanation: String {
        switch request.purpose {
        case .create:
            "Optionally choose a password to encrypt the local seed vault. Leave it blank to store the seed without encryption. The password does not affect the derived keys."
        case .unlock:
            "This vault is password protected. Enter its password to unlock the identity."
        }
    }

    /// Create asks twice to guard against a typo; the entry can't be verified,
    /// so a mismatch there would silently create a different identity.
    private var needsConfirmation: Bool { request.purpose == .create }

    private var canSubmit: Bool {
        if isUnlock { return !passphrase.isEmpty }
        return passphrase == confirmation
    }

    private var submitLabel: String {
        switch request.purpose {
        case .create: "Create"
        case .unlock: "Unlock"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.title3.weight(.semibold))
            Text(explanation)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            SecureField(isUnlock ? "Password" : "Password (optional)", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .onSubmit { if canSubmit { submit() } }
            if needsConfirmation {
                SecureField("Confirm password", text: $confirmation)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { if canSubmit { submit() } }
                if !confirmation.isEmpty && passphrase != confirmation {
                    Text("Passwords don’t match.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }

            HStack {
                Button("Cancel", role: .cancel) {
                    app.cancelPassphrase()
                    dismiss()
                }
                Spacer()
                Button(submitLabel) { submit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit)
                    .frame(minWidth: 112)
            }
            .padding(.top, 4)
        }
        .padding(28)
        .frame(width: 420)
        .onAppear { focused = true }
    }

    private func submit() {
        app.submitPassphrase(passphrase)
        dismiss()
    }
}

private struct ResetSeedSheet: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmation = ""
    @FocusState private var confirmationFocused: Bool

    private var needsTypedConfirmation: Bool { app.backupVerifiedAt == nil }
    private var canDelete: Bool { !needsTypedConfirmation || confirmation == "DELETE" }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Remove the Seed from This Mac?")
                .font(.title3.weight(.semibold))
            Label(
                app.backupVerifiedAt == nil ? "This recovery phrase has never been verified." : "Recovery phrase verified \(app.backupVerifiedAt!.formatted(date: .abbreviated, time: .omitted)).",
                systemImage: app.backupVerifiedAt == nil ? "exclamationmark.triangle.fill" : "checkmark.shield.fill"
            )
            .foregroundStyle(app.backupVerifiedAt == nil ? .red : .green)
            Text("Deleting the seed permanently removes this identity from the Mac. Installed aliases, Git settings, SSH settings, and launch agents are separate and can be removed from Settings.")
                .font(.callout)
                .foregroundStyle(.secondary)
            if needsTypedConfirmation {
                Text("Type DELETE to confirm without a verified backup.")
                    .font(.caption)
                TextField("DELETE", text: $confirmation)
                    .textFieldStyle(.roundedBorder)
                    .focused($confirmationFocused)
            }
            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Delete Seed", role: .destructive) {
                    app.resetSeed()
                    dismiss()
                }
                .disabled(!canDelete)
            }
        }
        .padding(28)
        .frame(width: 500)
        .onAppear { confirmationFocused = needsTypedConfirmation }
    }
}

private struct RestoreSheet: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var words = Array(repeating: "", count: 24)
    @State private var passphrase = ""
    @State private var passphraseConfirmation = ""
    @State private var confirmingReplacement = false
    @FocusState private var focusedWord: Int?

    private var isComplete: Bool {
        words.allSatisfy { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    /// Confirm a supplied password to avoid making the restored vault inaccessible.
    private var passphraseMatches: Bool {
        passphrase.isEmpty || passphrase == passphraseConfirmation
    }

    private var phrase: String {
        words.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.joined(separator: " ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Restore from Recovery Phrase")
                .font(.title3.weight(.semibold))
            Text("Enter your 24-word BIP39 phrase, or paste the whole phrase into any box to fill the rest.")
                .font(.callout)
                .foregroundStyle(.secondary)

            MnemonicColumns(spacing: 12, columnSpacing: 18, labelWidth: 24) { index in
                TextField("", text: Binding(
                    get: { words[index] },
                    set: { distribute($0, from: index) }
                ))
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("Recovery word \(index + 1)")
                .frame(width: 104)
                .focused($focusedWord, equals: index)
            }
            .padding(.top, 4)
            .padding(.bottom, 2)

            VStack(alignment: .leading, spacing: 4) {
                Text("Vault password (optional)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                SecureField("Leave blank for an unencrypted vault", text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                SecureField("Confirm password", text: $passphraseConfirmation)
                    .textFieldStyle(.roundedBorder)
                if !passphraseConfirmation.isEmpty && !passphraseMatches {
                    Text("Passwords don’t match.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }

            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
                Button("Restore") {
                    if app.hasSeed { confirmingReplacement = true }
                    else { beginRestore() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(app.isBusy || !isComplete || !passphraseMatches)
                .frame(minWidth: 112)
            }
            .padding(.top, 4)
        }
        .padding(28)
        // Sheets are clamped to ~75% of the window width (~675pt at the
        // 900pt window), so the grid (4 × 134 + 3 × 18 = 590pt) plus padding
        // must stay under that.
        .frame(width: 660)
        .onAppear { focusedWord = 0 }
        .onChange(of: app.restoreCompletedID) { _, completed in
            if completed != nil { dismiss() }
        }
        .confirmationDialog(
            "Replace the identity stored on this Mac?",
            isPresented: $confirmingReplacement
        ) {
            Button("Replace Identity", role: .destructive) { beginRestore() }
        } message: {
            if let fingerprint = app.identity?.pgp.fingerprint {
                Text("The current identity (OpenPGP fingerprint …\(fingerprint.suffix(16))) will be replaced after the imported identity is validated. Installed integrations will require repair.")
            } else {
                Text("The current stored identity will be replaced after the imported identity is validated. Installed integrations will require repair.")
            }
        }
    }

    private func beginRestore() {
        app.restore(fromPhrase: phrase, passphrase: passphrase)
    }

    /// Support pasting a full phrase into any box: split on whitespace and fill
    /// forward from that index; a single word just sets its own box.
    private func distribute(_ value: String, from index: Int) {
        let parts = value.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        if parts.count > 1 {
            for (offset, word) in parts.enumerated() where index + offset < words.count {
                words[index + offset] = word.lowercased()
            }
        } else {
            words[index] = value.lowercased()
        }
    }

}

private struct BackupDrillSheet: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.dismiss) private var dismiss
    let session: BackupDrillSession
    @State private var answers: [String]
    @FocusState private var focusedAnswer: Int?

    init(session: BackupDrillSession) {
        self.session = session
        self._answers = State(initialValue: Array(repeating: "", count: session.wordIndices.count))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Verify Recovery Phrase")
                .font(.title3.weight(.semibold))
            Text("Enter the exact words at the prompted positions. No full phrase is shown.")
                .font(.callout)
                .foregroundStyle(.secondary)

            ForEach(Array(session.wordIndices.enumerated()), id: \.offset) { offset, position in
                HStack {
                    Text("Word \(position + 1)")
                        .frame(width: 85, alignment: .leading)
                    TextField("", text: $answers[offset])
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Recovery word \(position + 1)")
                        .focused($focusedAnswer, equals: offset)
                }
            }

            HStack {
                Button("Cancel", role: .cancel) {
                    dismiss()
                    app.dismissBackupDrill()
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Verify") {
                    app.submitBackupDrill(answers: answers)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(app.isBusy || answers.contains { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty })
            }
            .padding(.top, 4)
        }
        .padding(28)
        .frame(width: 420)
        .onAppear {
            answers = Array(repeating: "", count: session.wordIndices.count)
            focusedAnswer = 0
        }
    }
}
