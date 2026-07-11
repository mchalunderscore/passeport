import Foundation

enum IntegrationHealth: Equatable, Sendable {
    case notConfigured
    case working
    case broken(String)

    var title: String {
        switch self {
        case .notConfigured: "Not configured"
        case .working: "Installed"
        case .broken: "Configured but broken"
        }
    }
}

private func managedDirectory(_ name: String) -> URL {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("Passeport", isDirectory: true)
        .appendingPathComponent(name, isDirectory: true)
}

func managedCommandHealth(command: String, directory: String) -> IntegrationHealth {
    let target = managedDirectory(directory).appendingPathComponent(command)
    let link = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/\(command)")
    let targetExists = FileManager.default.isExecutableFile(atPath: target.path)
    let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: link.path)
    guard targetExists || destination != nil else { return .notConfigured }
    let resolved = destination.map { URL(fileURLWithPath: $0, relativeTo: link.deletingLastPathComponent()).standardized.path }
    return targetExists && resolved == target.standardized.path
        ? .working
        : .broken("The managed command or its ~/.local/bin link is missing or points somewhere else.")
}

func removeManagedCommandLinks(names: [String], directory: String) throws {
    let fm = FileManager.default
    let managed = managedDirectory(directory)
    let bin = fm.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin", isDirectory: true)
    for name in names {
        let link = bin.appendingPathComponent(name)
        if let destination = try? fm.destinationOfSymbolicLink(atPath: link.path) {
            let resolved = URL(fileURLWithPath: destination, relativeTo: bin).standardized.path
            if resolved.hasPrefix(managed.standardized.path + "/") { try fm.removeItem(at: link) }
        }
    }
    if fm.fileExists(atPath: managed.path) { try fm.removeItem(at: managed) }
}

/// Locates external CLI binaries that Passeport flows shell out to but does
/// not itself provide (currently optional Pluggable Scdaemon GnuPG). Passeport deliberately
/// ships no in-app installer: the user supplies these binaries via their package
/// manager, the official installer, or `scripts/install-tooling.sh`, and keeps
/// them on `PATH` (or in `~/.local/bin`, which the app also searches). This type
/// only *discovers* them so the UI can gate the "Configure…" actions.
enum ToolingInstaller {
    static let localBinURL = URL(fileURLWithPath: NSHomeDirectory())
        .appendingPathComponent(".local/bin", isDirectory: true)

    /// The user's real `PATH`, as reported by their login shell. A GUI app
    /// launched from Finder/Xcode inherits only the minimal launchd `PATH`, not
    /// the shell `PATH`, so tools the user installed (Homebrew, grimoire, …) are
    /// invisible otherwise. Resolved once by asking the login shell, and cached.
    static let loginShellPaths: [String] = resolveLoginShellPaths()

    static let gnuPGBinaryNames = ["gpg"]

    static var gnuPGPath: String? {
        resolveTool(named: gnuPGBinaryNames)?.path
    }

    static var hasGnuPG: Bool {
        resolveTool(named: gnuPGBinaryNames) != nil
    }

    // MARK: - Discovery

    /// Return the first executable matching any of `names`, searching
    /// `~/.local/bin` first, then each directory on the user's login-shell
    /// `PATH`.
    private static func resolveTool(named names: [String]) -> URL? {
        var searchPaths: [String] = [localBinURL.path]
        searchPaths.append(contentsOf: loginShellPaths)

        for dir in searchPaths {
            for name in names {
                let candidate = "\(dir)/\(name)"
                if isExecutable(candidate) {
                    return URL(fileURLWithPath: candidate)
                }
            }
        }
        return nil
    }

    private static func isExecutable(_ path: String) -> Bool {
        FileManager.default.isExecutableFile(atPath: path)
    }

    /// The `PATH` as seen by the user's LOGIN shell (`.zshenv` + `.zprofile`).
    /// Deliberately non-interactive: interactive init (prompt frameworks like
    /// Powerlevel10k's instant-prompt, or rc-file programs) can swallow the
    /// query's output or block on a TTY, so `-i` is avoided. Falls back to the
    /// inherited env `PATH` if the shell can't be run; bounded by a timeout.
    private static func resolveLoginShellPaths() -> [String] {
        let fallback = inheritedPaths()
        let shell = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        guard FileManager.default.isExecutableFile(atPath: shell) else { return fallback }

        let marker = "__PASSEPORT_PATH__"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: shell)
        // Print PATH between markers so any startup-file chatter on stdout is
        // easy to strip. POSIX-ish; a non-POSIX login shell (e.g. nushell) will
        // just error and we fall back to the inherited PATH.
        process.arguments = ["-lc", "printf '%s' \"\(marker)$PATH\(marker)\""]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return fallback
        }

        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            process.waitUntilExit()
            done.signal()
        }
        if done.wait(timeout: .now() + 5) == .timedOut {
            process.terminate()
            return fallback
        }

        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8),
              let first = output.range(of: marker),
              let second = output.range(of: marker, range: first.upperBound..<output.endIndex)
        else {
            return fallback
        }
        let dirs = output[first.upperBound..<second.lowerBound]
            .split(separator: ":", omittingEmptySubsequences: true)
            .map(String.init)
        return dirs.isEmpty ? fallback : dirs
    }

    private static func inheritedPaths() -> [String] {
        let pathEnv = ProcessInfo.processInfo.environment["PATH"] ?? ""
        if pathEnv.isEmpty { return [] }
        return pathEnv
            .split(separator: ":", omittingEmptySubsequences: true)
            .map(String.init)
    }
}
