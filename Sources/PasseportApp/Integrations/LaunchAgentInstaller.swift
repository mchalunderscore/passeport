import Foundation

/// Installs a LaunchAgent that socket-activates Passeport: launchd owns the
/// scd socket and starts the app when gpg first connects, so the smartcard
/// works even if the app was not already running.
///
/// Note: the installed job launches the app bundle. Because it is a GUI app,
/// an on-demand launch will bring it to the foreground; running it as a
/// background accessory is a future refinement.
enum LaunchAgentInstaller {
    static let label = "lol.mchal.passeport.bridge"

    enum InstallError: LocalizedError {
        case noExecutable
        case launchctlFailed(String)

        var errorDescription: String? {
            switch self {
            case .noExecutable:
                "Could not determine the app executable path."
            case .launchctlFailed(let message):
                "launchctl failed: \(message)"
            }
        }
    }

    static var plistURL: URL {
        FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("LaunchAgents", isDirectory: true)
            .appendingPathComponent("\(label).plist")
    }

    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    static func install() throws {
        guard let executable = Bundle.main.executablePath else {
            throw InstallError.noExecutable
        }
        let socketPath = ScdBridge.socketURL.path
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable],
            "Sockets": [
                ScdBridge.launchdSocketName: [
                    "SockPathName": socketPath,
                    "SockType": "stream",
                    "SockPathMode": 0o600,
                ]
            ],
            // No RunAtLoad: launchd starts the app on the first connection.
            "ProcessType": "Interactive",
        ]

        let url = plistURL
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let data = try PropertyListSerialization.data(
            fromPropertyList: plist, format: .xml, options: 0
        )
        try data.write(to: url)

        // A stale socket file blocks launchd from creating its own.
        unlink(socketPath)
        let domain = "gui/\(getuid())"
        try runLaunchctl(["bootout", domain, url.path], allowFailure: true)
        try runLaunchctl(["bootstrap", domain, url.path])
    }

    static func uninstall() throws {
        let domain = "gui/\(getuid())"
        try runLaunchctl(["bootout", domain, plistURL.path], allowFailure: true)
        try? FileManager.default.removeItem(at: plistURL)
    }

    private static func runLaunchctl(_ args: [String], allowFailure: Bool = false) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = args
        let errPipe = Pipe()
        process.standardError = errPipe
        try process.run()
        let errorOut = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        if process.terminationStatus != 0 && !allowFailure {
            let message = String(data: errorOut, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? "exit \(process.terminationStatus)"
            throw InstallError.launchctlFailed(message)
        }
    }
}
