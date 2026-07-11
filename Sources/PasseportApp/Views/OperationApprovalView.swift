import AppKit
import SwiftUI

/// Structured description of a private operation awaiting the user's approval.
struct ApprovalPrompt {
    enum Kind {
        case sign
        case sshAuth
        case decrypt
        case unknown
    }

    let kind: Kind
    let keyref: String
    let byteCount: Int
    /// Hex of the leading bytes being signed, empty when not applicable.
    let hexPreview: String
    let requestingClient: String
    let summary: String

    /// Classify a bridge request (JSON) into an approval prompt, or nil if it
    /// needs no confirmation (e.g. a public-key lookup during enumeration).
    ///
    /// The authentication subkey (OPENPGP.3) is only ever used for SSH — via
    /// PKAUTH for a login, or an SSHSIG blob for `ssh-keygen -Y`. A real SSH
    /// login doesn't carry the SSHSIG magic, so classification is by slot, not
    /// by payload.
    static func classify(request: String) -> ApprovalPrompt? {
        guard let metadata = OperationRequestMetadata.parse(requestLine: request) else {
            return ApprovalPrompt(
                kind: .unknown,
                keyref: "?",
                byteCount: 0,
                hexPreview: "",
                requestingClient: OperationRequestMetadata.defaultClient,
                summary: "unknown operation"
            )
        }

        if metadata.kind == .keyLookup {
            return nil
        }
        return metadata.toApprovalPrompt()
    }
}

/// A borderless window that can still take keyboard focus (for the Return /
/// Escape shortcuts on the buttons).
private final class KeyablePanel: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

/// Shows the approval panel modally and returns the user's decision.
@MainActor
enum OperationApproval {
    static func present(_ prompt: ApprovalPrompt) -> Bool {
        // Borderless + clear background so there is no titlebar gap and the
        // panel's own rounded corners show through.
        let window = KeyablePanel(
            contentRect: NSRect(x: 0, y: 0, width: 340, height: 100),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = true
        window.isMovableByWindowBackground = true
        window.level = .modalPanel

        var approved = false
        let view = OperationApprovalView(prompt: prompt) { decision in
            approved = decision
            NSApp.stopModal()
        }
        let hosting = NSHostingView(rootView: view)
        hosting.setFrameSize(hosting.fittingSize)
        window.setContentSize(hosting.fittingSize)
        window.contentView = hosting
        window.center()

        // Remember who was frontmost so focus can be returned afterward —
        // otherwise activating to show the panel leaves the main window in
        // front of whatever the user was actually working in.
        let previousApp = NSWorkspace.shared.frontmostApplication

        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        NSApp.runModal(for: window)
        window.orderOut(nil)

        if let previousApp,
           previousApp.processIdentifier != NSRunningApplication.current.processIdentifier {
            previousApp.activate(from: .current)
        }
        return approved
    }
}

/// Shows the password-unlock panel modally and returns the entered password,
/// or nil if the user cancelled. Used when a private operation needs a
/// password-protected vault that isn't unlocked yet.
@MainActor
enum PassphraseUnlock {
    static func present(errorMessage: String?) -> String? {
        let window = KeyablePanel(
            contentRect: NSRect(x: 0, y: 0, width: 360, height: 140),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = true
        window.isMovableByWindowBackground = true
        window.level = .modalPanel

        var result: String?
        let view = PassphrasePromptView(errorMessage: errorMessage) { entered in
            result = entered
            NSApp.stopModal()
        }
        let hosting = NSHostingView(rootView: view)
        hosting.setFrameSize(hosting.fittingSize)
        window.setContentSize(hosting.fittingSize)
        window.contentView = hosting
        window.center()

        let previousApp = NSWorkspace.shared.frontmostApplication
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        NSApp.runModal(for: window)
        window.orderOut(nil)

        if let previousApp,
           previousApp.processIdentifier != NSRunningApplication.current.processIdentifier {
            previousApp.activate(from: .current)
        }
        return result
    }
}

private struct PassphrasePromptView: View {
    let errorMessage: String?
    /// nil = cancelled, non-nil = the entered password.
    let onComplete: (String?) -> Void
    @State private var passphrase = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Password required", systemImage: "key.horizontal.fill")
                .font(.headline)
            Text("This vault is password protected. Enter its password to unlock for this operation.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("Password", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .onSubmit { if !passphrase.isEmpty { onComplete(passphrase) } }
            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            HStack {
                Button("Cancel", role: .cancel) { onComplete(nil) }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Unlock") { onComplete(passphrase) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(passphrase.isEmpty)
            }
        }
        .padding(18)
        .frame(width: 360)
        .panelChrome()
        .onAppear { focused = true }
    }
}

private struct PanelChromeModifier: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        if reduceTransparency {
            content
                .background(Color(nsColor: .windowBackgroundColor), in: shape)
                .overlay(shape.strokeBorder(.separator, lineWidth: contrast == .increased ? 2 : 1))
        } else if #available(macOS 26.0, *) {
            content.glassEffect(.regular, in: shape)
        } else {
            content
                .background(.regularMaterial)
                .clipShape(shape)
                .overlay(shape.strokeBorder(.quaternary, lineWidth: contrast == .increased ? 2 : 1))
        }
    }
}

private extension View {
    /// Rounded Liquid Glass chrome for the borderless approval panel on
    /// macOS 26, with a material fallback on older systems.
    @ViewBuilder func panelChrome() -> some View {
        modifier(PanelChromeModifier())
    }
}

struct OperationApprovalView: View {
    let prompt: ApprovalPrompt
    let onDecision: (Bool) -> Void

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 10) {
                VStack(spacing: 8) {
                    Text("Request from \(prompt.requestingClient)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)

                    Circle()
                        .fill(tint.opacity(0.15))
                        .frame(width: 58, height: 58)
                        .overlay(
                            Image(systemName: icon)
                                .font(.system(size: 27, weight: .semibold))
                                .foregroundStyle(tint)
                        )
                        .accessibilityHidden(true)

                    if !prompt.summary.isEmpty {
                        Text(prompt.summary)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }

                    Text(title)
                        .font(.headline)

                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)

                    if !prompt.hexPreview.isEmpty {
                        dataBlock
                            .padding(.top, 2)
                    }
                }
                .padding(.horizontal, 22)
                .padding(.top, 22)
                .padding(.bottom, 16)

                Divider()

                HStack(spacing: 12) {
                    Button("Deny") { onDecision(false) }
                        .keyboardShortcut(.cancelAction)
                        .frame(maxWidth: .infinity, minHeight: 34)
                    Button("Approve") { onDecision(true) }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                        .frame(maxWidth: .infinity, minHeight: 34)
                }
                .controlSize(.large)
                .padding(16)
            }
        }
        .frame(width: 340)
        .panelChrome()
    }

    private var dataBlock: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Data being signed · \(prompt.byteCount) bytes")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(groupedHex)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    /// Space the preview hex into byte pairs, ending with an ellipsis.
    private var groupedHex: String {
        let chars = Array(prompt.hexPreview)
        let pairs = stride(from: 0, to: chars.count, by: 2).map { start -> String in
            String(chars[start..<min(start + 2, chars.count)])
        }
        return pairs.joined(separator: " ") + " …"
    }

    private var icon: String {
        switch prompt.kind {
        case .sign: "signature"
        case .sshAuth: "terminal.fill"
        case .decrypt: "lock.open.fill"
        case .unknown: "questionmark.circle.fill"
        }
    }

    private var tint: Color {
        switch prompt.kind {
        case .sign: .blue
        case .sshAuth: .indigo
        case .decrypt: .teal
        case .unknown: .orange
        }
    }

    private var title: String {
        switch prompt.kind {
        case .sign: "Approve signature?"
        case .sshAuth: "Approve SSH authentication?"
        case .decrypt: "Approve decryption?"
        case .unknown: "Approve operation?"
        }
    }

    private var subtitle: String {
        switch prompt.kind {
        case .sign:
            "gpg-agent wants to sign with your OpenPGP key (\(prompt.keyref))."
        case .sshAuth:
            "An SSH client wants to authenticate as you using your authentication key (\(prompt.keyref))."
        case .decrypt:
            "gpg-agent wants to decrypt a message with your encryption subkey (\(prompt.keyref))."
        case .unknown:
            "Passeport received a request it could not describe."
        }
    }
}
