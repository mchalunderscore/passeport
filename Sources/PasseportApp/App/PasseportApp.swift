import AppKit
import SwiftUI

@main
struct PasseportApp: App {
    @StateObject private var appModel = AppModel()

    init() {
        // The bridge and ssh-agent sockets write to peers that can hang up
        // mid-operation (e.g. ssh Ctrl-C'd while an approval prompt is up);
        // without this, that write's SIGPIPE kills the app. Writers see a
        // plain EPIPE instead.
        signal(SIGPIPE, SIG_IGN)
        // A single-window utility has no use for window tabs; this also
        // removes the "Show Tab Bar" items from the View menu.
        NSWindow.allowsAutomaticWindowTabbing = false
    }

    var body: some Scene {
        WindowGroup("Passeport", id: "main") {
            ContentView()
                .environmentObject(appModel)
                .frame(minWidth: 860, minHeight: 600)
                .task {
                    // Skip launch side effects when hosting unit tests.
                    guard NSClassFromString("XCTestCase") == nil else { return }
#if DEBUG
                    // Keep accessibility/UI audit builds deterministic and
                    // independent of the user's identity vault and background agents.
                    guard !CommandLine.arguments.contains("--accessibility-audit") else { return }
#endif
                    appModel.refreshSeedPresence()
                    appModel.runContractSelfTest()
                    appModel.startBridgeIfNeeded()
                    appModel.checkForUpdates()
                }
        }
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }

        MenuBarExtra("Passeport", image: "PasseportLogo") {
            MenuBarContent()
                .environmentObject(appModel)
        }

        Settings {
            SettingsSection()
                .environmentObject(appModel)
                .frame(width: 680, height: 620)
        }
    }
}

private struct MenuBarContent: View {
    @EnvironmentObject private var app: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Label(
            app.identity == nil ? "Identity locked" : "Identity ready",
            systemImage: app.identity == nil ? "lock" : "checkmark.seal.fill"
        )

        Divider()

        Button("Open Passeport") {
            openWindow(id: "main")
            NSApplication.shared.activate(ignoringOtherApps: true)
        }

        Menu("Copy Keys") {
            Button("SSH Public Key") {
                guard let identity = app.identity else { return }
                app.copy(identity.ssh.publicKey, label: "SSH public key")
            }

            Button("OpenPGP Public Key") {
                guard let identity = app.identity else { return }
                app.copy(identity.pgp.publicKey, label: "OpenPGP public key")
            }

            Button("age Recipient") {
                guard let identity = app.identity else { return }
                app.copy(identity.age.recipient, label: "age recipient")
            }

            Button("minisign Public Key") {
                guard let identity = app.identity else { return }
                app.copy(identity.minisign.publicKey, label: "minisign public key")
            }
        }
        .disabled(app.identity == nil)

        Button(app.sshAgentRunning ? "Stop SSH Agent" : "Start SSH Agent") {
            app.toggleSSHAgent()
        }
        .disabled(app.isBusy)

        Button(app.bridgeRunning ? "Stop GnuPG Bridge" : "Start GnuPG Bridge") {
            app.toggleBridge()
        }
        .disabled(app.isBusy)

        Divider()

        SettingsLink {
            Text("Settings…")
        }

        Button("Quit Passeport") {
            NSApplication.shared.terminate(nil)
        }
    }
}
