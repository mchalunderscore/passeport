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
        WindowGroup {
            ContentView()
                .environmentObject(appModel)
                .frame(minWidth: 860, minHeight: 600)
                .task {
                    // Skip launch side effects when hosting unit tests.
                    guard NSClassFromString("XCTestCase") == nil else { return }
                    appModel.refreshSeedPresence()
                    appModel.runContractSelfTest()
                    appModel.startBridgeIfNeeded()
                }
        }
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }

        MenuBarExtra("Passeport", image: "Symbolic") {
            MenuBarContent()
                .environmentObject(appModel)
        }
    }
}

private struct MenuBarContent: View {
    @EnvironmentObject private var app: AppModel

    var body: some View {
        Text(app.bridgeRunning ? "GnuPG bridge: running" : "GnuPG bridge: stopped")

        Button(app.bridgeRunning ? "Stop Bridge" : "Start Bridge") {
            app.toggleBridge()
        }
        .disabled(app.isBusy)

        Button("Configure GnuPG…") {
            app.configureGnuPG()
        }
        .disabled(app.isBusy || app.identity == nil)

        Divider()

        Button("Quit Passeport") {
            NSApplication.shared.terminate(nil)
        }
    }
}
