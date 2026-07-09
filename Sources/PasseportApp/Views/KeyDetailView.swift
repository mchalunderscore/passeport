import SwiftUI

struct KeyDetailView: View {
    @EnvironmentObject private var app: AppModel

    var body: some View {
        if let identity = app.identity {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    PublicKeySection(identity: identity)
                    PrivateKeySection(identity: identity)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            ContentUnavailableView(
                "No Keys In Memory",
                systemImage: "lock",
                description: Text("Derive keys from your seed to see them here.")
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

private struct PublicKeySection: View {
    @EnvironmentObject private var app: AppModel
    let identity: DerivedIdentity

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(
                title: "Public Material",
                actions: [
                    ActionButton(label: "Copy SSH", systemImage: "doc.on.doc") {
                        app.copy(identity.ssh.publicKey, label: "SSH public key")
                    },
                    ActionButton(label: "Copy age", systemImage: "doc.on.doc") {
                        app.copy(identity.age.recipient, label: "age recipient")
                    },
                    ActionButton(label: "Export", systemImage: "square.and.arrow.down") {
                        app.exportPublicBundle()
                    }
                ]
            )

            KeyField(title: "SSH public key (OpenPGP auth subkey)", value: identity.ssh.publicKey)
            KeyField(title: "OpenPGP fingerprint", value: identity.pgp.fingerprint, minHeight: 40)
            KeyField(title: "OpenPGP public key", value: identity.pgp.publicKey, minHeight: 180)
            KeyField(title: "age recipient (OpenPGP encryption subkey)", value: identity.age.recipient)
        }
    }
}

private struct PrivateKeySection: View {
    @EnvironmentObject private var app: AppModel
    let identity: DerivedIdentity

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(
                title: "Private Material",
                actions: [
                    ActionButton(label: app.showingPrivateMaterial ? "Hide" : "Reveal", systemImage: app.showingPrivateMaterial ? "eye.slash" : "eye") {
                        app.showingPrivateMaterial.toggle()
                    },
                    ActionButton(label: "Export", systemImage: "square.and.arrow.down") {
                        app.exportPrivateBundle()
                    }
                ]
            )

            if app.showingPrivateMaterial {
                KeyField(title: "OpenPGP secret key", value: identity.pgp.secretKey, minHeight: 220)
            } else {
                Text("Private keys are derived in memory and hidden until explicitly revealed.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct SectionHeader: View {
    let title: String
    let actions: [ActionButton]

    var body: some View {
        HStack {
            Text(title)
                .font(.title3.weight(.semibold))
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

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.headline)
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
