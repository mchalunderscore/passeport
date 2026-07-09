import SwiftUI

enum AppSection: String, CaseIterable, Identifiable {
    case keys = "Keys"
    case backup = "Backup & Recovery"
    case integrations = "Integrations"
    case options = "Options"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .keys: "key.fill"
        case .backup: "lifepreserver"
        case .integrations: "terminal"
        case .options: "gearshape"
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
        case .keys: KeysSection(showingRestore: $showingRestore)
        case .backup: BackupSection(showingRestore: $showingRestore)
        case .integrations: IntegrationsSection()
        case .options: OptionsSection()
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
            Image("Symbolic")
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
    }
}

// MARK: - Keys

private struct KeysSection: View {
    @EnvironmentObject private var app: AppModel
    @Binding var showingRestore: Bool
    @State private var confirmingReset = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            GroupBox {
                VStack(alignment: .leading, spacing: 14) {
                    if app.hasSeed {
                        HStack {
                            secretStatus
                            Spacer()
                            HStack {
                                Button {
                                    app.deriveKeys()
                                } label: {
                                    Label("Derive Keys", systemImage: "lock.open")
                                }
                                .disabled(app.isBusy)
                                Button(role: .destructive) {
                                    confirmingReset = true
                                } label: {
                                    Label("Reset", systemImage: "arrow.counterclockwise")
                                }
                                .disabled(app.isBusy)
                            }
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
            .confirmationDialog(
                "Remove the seed from this Mac?",
                isPresented: $confirmingReset
            ) {
                Button("Delete Seed", role: .destructive) { app.resetSeed() }
            } message: {
                Text("The seed is deleted from this Mac. Unless you have its 24-word recovery phrase, the derived keys can never be recreated.")
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
                        Text("Deriving identity from seed…")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ContentUnavailableView(
                        "No Keys In Memory",
                        systemImage: "lock",
                        description: Text("Derive keys from your seed to see them here.")
                    )
                    .frame(maxWidth: .infinity, alignment: .leading)
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
    }

    @ViewBuilder private var secretStatus: some View {
        Label("Seed present on this Mac", systemImage: "checkmark.seal.fill")
            .foregroundStyle(.green)
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
                Spacer(minLength: 0)
            }
            .padding(24)
        }
    }
}

// MARK: - Integrations

private struct IntegrationsSection: View {
    @EnvironmentObject private var app: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox {
                    VStack(alignment: .leading, spacing: 14) {
                        if app.bridgeRunning {
                            Label("Bridge running — gpg-agent can use the virtual card", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                        } else {
                            Label("Bridge stopped", systemImage: "pause.circle")
                                .foregroundStyle(.secondary)
                        }

                        Text("Serves the derived identity to gpg-agent as an OpenPGP smartcard. “Configure GnuPG” writes the gpg-agent settings and imports the public key for you.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        HStack {
                            Button {
                                app.toggleBridge()
                            } label: {
                                Label(app.bridgeRunning ? "Stop Bridge" : "Start Bridge",
                                      systemImage: app.bridgeRunning ? "stop.circle" : "play.circle")
                            }
                            .disabled(app.isBusy)

                            Button {
                                app.configureGnuPG()
                            } label: {
                                Label("Configure GnuPG", systemImage: "gearshape")
                            }
                            .disabled(app.isBusy || app.identity == nil)
                            .help(app.identity == nil ? "Derive your keys first to enable this." : "Write the gpg-agent config and import the public key.")
                        }
                        if app.identity == nil {
                            RequiresKeysHint()
                        }
                    }
                    .padding(6)
                } label: {
                    Label("GnuPG Smartcard Bridge", systemImage: "creditcard")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 14) {
                        if app.sshAgentRunning {
                            Label("Agent running — ssh can use your auth key directly", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                        } else {
                            Label("Agent stopped", systemImage: "pause.circle")
                                .foregroundStyle(.secondary)
                        }

                        Text("A built-in ssh-agent serving your auth key — no GnuPG needed. “Configure SSH” points ~/.ssh/config at it; every signature still asks for approval per your settings.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        HStack {
                            Button {
                                app.toggleSSHAgent()
                            } label: {
                                Label(app.sshAgentRunning ? "Stop Agent" : "Start Agent",
                                      systemImage: app.sshAgentRunning ? "stop.circle" : "play.circle")
                            }
                            .disabled(app.isBusy)

                            Button {
                                app.configureSSH()
                            } label: {
                                Label("Configure SSH", systemImage: "gearshape")
                            }
                            .disabled(app.isBusy)

                            Button {
                                if let key = app.identity?.ssh.publicKey {
                                    app.copy(key, label: "SSH public key")
                                }
                            } label: {
                                Label("Copy Public Key", systemImage: "doc.on.doc")
                            }
                            .disabled(app.identity == nil)
                            .help(app.identity == nil ? "Derive your keys first to enable this." : "Copy the SSH public key for GitHub and authorized_keys.")
                        }
                    }
                    .padding(6)
                } label: {
                    Label("Native SSH Agent", systemImage: "terminal")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("Sign git commits and tags with your Passeport identity. Choose GPG (OpenPGP signatures via gpg) or SSH (signed through the native agent, no GnuPG needed). Both show as Verified on GitHub.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        HStack {
                            Button {
                                app.configureGitSigning()
                            } label: {
                                Label("Set Up Git Signing (GPG)", systemImage: "checkmark.seal")
                            }
                            .disabled(app.isBusy || app.identity == nil)
                            .help(app.identity == nil ? "Derive your keys first to enable this." : "Configure git to sign with your OpenPGP key via gpg.")

                            Button {
                                app.configureGitSigningSSH()
                            } label: {
                                Label("Set Up Git Signing (SSH)", systemImage: "terminal")
                            }
                            .disabled(app.isBusy || app.identity == nil)
                            .help(app.identity == nil ? "Derive your keys first to enable this." : "Configure git to sign with SSH (gpg.format=ssh), signed through the native agent.")
                        }
                        if app.identity == nil {
                            RequiresKeysHint()
                        }
                    }
                    .padding(6)
                } label: {
                    Label("Git", systemImage: "arrow.triangle.branch")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("Encrypt and decrypt files with age — no GnuPG needed. Passeport installs an age plugin; decryption is Touch ID-gated through the app. Files encrypted with age are not interoperable with gpg encryption.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        HStack {
                            Button {
                                app.configureAge()
                            } label: {
                                Label("Set Up age Encryption", systemImage: "lock.doc")
                            }
                            .disabled(app.isBusy || app.identity == nil)
                            .help(app.identity == nil ? "Derive your keys first to enable this." : "Install age-plugin-passeport and show your recipient.")

                            if let recipient = app.ageRecipient {
                                Button {
                                    app.copy(recipient, label: "age recipient")
                                } label: {
                                    Label("Copy Recipient", systemImage: "doc.on.doc")
                                }
                            }
                        }
                        if let recipient = app.ageRecipient {
                            Text(recipient)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        if app.identity == nil {
                            RequiresKeysHint()
                        }
                    }
                    .padding(6)
                } label: {
                    Label("age Encryption", systemImage: "lock.doc")
                }
                Spacer(minLength: 0)
            }
            .padding(24)
        }
    }
}

// MARK: - Options

private struct OptionsSection: View {
    @EnvironmentObject private var app: AppModel

    var body: some View {
        Form {
            Section("Availability") {
                Toggle("Start bridge at login", isOn: $app.launchAtLogin)
                Toggle("Start Passeport on demand (background launcher)", isOn: Binding(
                    get: { app.backgroundLauncherInstalled },
                    set: { _ in app.toggleBackgroundLauncher() }
                ))
                .disabled(app.isBusy)
            }
            Section {
                Toggle("Confirm each signature or decryption", isOn: $app.confirmEachOperation)
                    Toggle("Require Touch ID for each operation", isOn: $app.requireTouchIDPerOperation)
            } header: {
                Text("Operation approval")
            } footer: {
                Text("Confirmation shows what is being signed before each operation — a check against a compromised gpg-agent using the key silently.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Auto-lock") {
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
                .pickerStyle(.segmented)
                .disabled(!app.autoLockOnIdle)
            }
            Section("Operation audit log") {
                if app.operationAuditEvents.isEmpty {
                    Text("No operations have been logged yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(app.operationAuditEvents) { event in
                        OperationAuditRow(event: event)
                    }
                }
                HStack {
                    Button("Refresh") { Task { await app.refreshOperationAuditLog() } }
                    Button("Clear") { app.clearOperationAuditLog() }
                        .foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
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
        Label("Derive your keys first in the Keys tab to enable this.", systemImage: "info.circle")
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
            Text(message)
                .font(.caption)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.15))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct StatusBar: View {
    @EnvironmentObject private var app: AppModel

    var body: some View {
        HStack {
            HStack(spacing: 7) {
                if app.isBusy {
                    ProgressView().controlSize(.small)
                }
                Text(app.status)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .glassCapsule()
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 20)
        .padding(.bottom, 14)
    }
}

extension View {
    /// Liquid Glass capsule on macOS 26, material fallback on older systems.
    @ViewBuilder func glassCapsule() -> some View {
        if #available(macOS 26.0, *) {
            glassEffect(.regular, in: Capsule())
        } else {
            background(.regularMaterial, in: Capsule())
                .overlay(Capsule().strokeBorder(.quaternary))
        }
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
                Button("Copy") { app.copy(phrase, label: "recovery phrase") }
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

private struct RestoreSheet: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var words = Array(repeating: "", count: 24)
    @FocusState private var focusedWord: Int?

    private var isComplete: Bool {
        words.allSatisfy { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
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
                .frame(width: 104)
                .focused($focusedWord, equals: index)
                .onKeyPress(.tab) {
                    moveFocus(from: index)
                    return .handled
                }
            }
            .padding(.top, 4)
            .padding(.bottom, 2)

            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
                Button("Restore") {
                    app.restore(fromPhrase: phrase)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isComplete)
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

    private func moveFocus(from index: Int) {
        focusedWord = min(index + 1, 23)
    }
}

private struct BackupDrillSheet: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.dismiss) private var dismiss
    let session: BackupDrillSession
    @State private var answers: [String]

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
                }
            }

            HStack {
                Button("Cancel", role: .cancel) {
                    dismiss()
                    app.dismissBackupDrill()
                }
                Spacer()
                Button("Verify") {
                    app.submitBackupDrill(answers: answers)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(app.isBusy)
            }
            .padding(.top, 4)
        }
        .padding(28)
        .frame(width: 420)
        .onAppear {
            answers = Array(repeating: "", count: session.wordIndices.count)
        }
    }
}
