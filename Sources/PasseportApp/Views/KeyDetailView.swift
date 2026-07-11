import SwiftUI

struct KeyDetailView: View {
    @EnvironmentObject private var app: AppModel

    var body: some View {
        if let identity = app.identity {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    PublicKeySection(identity: identity)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            ContentUnavailableView(
                "No Keys In Memory",
                systemImage: "lock",
                description: Text("Unlock your identity to see its public keys here.")
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

private struct PublicKeySection: View {
    @EnvironmentObject private var app: AppModel
    let identity: DerivedIdentity

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                KeyField(
                    title: "SSH public key (OpenPGP auth subkey)",
                    value: identity.ssh.publicKey,
                    copyAction: { app.copy(identity.ssh.publicKey, label: "SSH public key") }
                )
                KeyField(
                    title: "OpenPGP public key",
                    value: identity.pgp.publicKey,
                    minHeight: 180,
                    copyAction: { app.copy(identity.pgp.publicKey, label: "OpenPGP public key") }
                )
                KeyField(
                    title: "age recipient (OpenPGP encryption subkey)",
                    value: identity.age.recipient,
                    copyAction: { app.copy(identity.age.recipient, label: "age recipient") }
                )
                KeyField(
                    title: "minisign public key (seed-derived Ed25519)",
                    value: identity.minisign.publicKey,
                    copyAction: { app.copy(identity.minisign.publicKey, label: "minisign public key") }
                )

                ActionBar(
                    actions: [
                        ActionButton(label: "Export Public Keys", systemImage: "square.and.arrow.down") {
                            app.exportPublicBundle()
                        }
                    ]
                )
            }
            .padding(6)
        } label: {
            Label("Public Keys", systemImage: "key")
        }
    }
}

private struct ActionBar: View {
    let actions: [ActionButton]

    var body: some View {
        HStack {
            Spacer()
            ForEach(actions) { action in
                Button(action: action.action) {
                    Label(action.label, systemImage: action.systemImage)
                }
                .buttonStyle(.bordered)
            }
        }
    }
}

private struct ActionButton: Identifiable {
    let id = UUID()
    let label: String
    let systemImage: String
    let action: () -> Void
}

private struct KeyField: View {
    let title: String
    let value: String
    var minHeight: CGFloat = 72
    var copyAction: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(.headline)
                Spacer()
                if let copyAction {
                    Button(action: copyAction) {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    .controlSize(.small)
                    .accessibilityLabel("Copy \(title)")
                }
            }
            ScrollView {
                Text(value)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(minHeight: minHeight)
            .background(.quaternary.opacity(0.35))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }
}
