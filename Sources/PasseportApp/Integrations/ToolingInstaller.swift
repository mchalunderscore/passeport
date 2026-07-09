import Foundation

/// Locates the external CLI binaries that Passeport flows shell out to but does
/// not itself provide (currently GnuPG and age/rage). Passeport deliberately
/// ships no in-app installer: the user supplies these binaries via their package
/// manager, the official installer, or `scripts/install-tooling.sh`, and keeps
/// them on `PATH` (or in `~/.local/bin`, which the app also searches). This type
/// only *discovers* them so the UI can gate the "Configure…" actions.
enum ToolingInstaller {
    static let localBinURL = URL(fileURLWithPath: NSHomeDirectory())
        .appendingPathComponent(".local/bin", isDirectory: true)

    /// The app bundle's `Contents/Helpers`, where the permissive toolchain
    /// (`rage`/`age`) is shipped. It holds no `gpg`, so this
    /// never makes the Mode 1 GnuPG detection resolve to our own drop-in.
    static let bundledHelpersURL = Bundle.main.bundleURL
        .appendingPathComponent("Contents/Helpers", isDirectory: true)

    /// The user's real `PATH`, as reported by their login shell. A GUI app
    /// launched from Finder/Xcode inherits only the minimal launchd `PATH`, not
    /// the shell `PATH`, so tools the user installed (Homebrew, grimoire, …) are
    /// invisible otherwise. Resolved once by asking the login shell, and cached.
    static let loginShellPaths: [String] = resolveLoginShellPaths()

    /// Accepted binary names, in preference order. `rage` (the Rust age
    /// implementation) is preferred over `age`; either satisfies the age flows.
    static let rageBinaryNames = ["rage", "age"]
    static let gnuPGBinaryNames = ["gpg"]

    static var gnuPGPath: String? {
        resolveTool(named: gnuPGBinaryNames)?.path
    }

    static var ragePath: String? {
        resolveTool(named: rageBinaryNames)?.path
    }

    static var hasGnuPG: Bool {
        resolveTool(named: gnuPGBinaryNames) != nil
    }

    static var hasRageOrAge: Bool {
        resolveTool(named: rageBinaryNames) != nil
    }

    // MARK: - Discovery

    /// Return the first executable matching any of `names`, searching
    /// `~/.local/bin` and the bundled Helpers first, then each directory on the
    /// user's login-shell `PATH`.
    private static func resolveTool(named names: [String]) -> URL? {
        var searchPaths: [String] = [localBinURL.path, bundledHelpersURL.path]
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
