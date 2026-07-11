import Foundation

/// Quoting for values embedded in generated shell scripts. Single-quote
/// wrapping keeps `$`, backticks, and backslashes literal; embedded single
/// quotes use the standard `'\''` escape. Shared by all configurators that
/// emit wrapper scripts.
enum ShellQuote {
    static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

/// One-shot GnuPG setup: writes the scdaemon wrapper, points `gpg-agent.conf`
/// at it, imports the public key, and creates the card stubs — the manual
/// steps from the README, done for the user.
///
/// Everything it touches is under the user's `GNUPGHOME` and Passeport's
/// Application Support directory. Existing `gpg-agent.conf` content is backed
/// up before modification and edits are idempotent.
enum GnuPGConfigurator {
    private struct ManagedState: Codable {
        let previousScdaemonLine: String?
        let addedSSHSupport: Bool
        let managedScdaemonLine: String
    }

    private static var stateURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport", isDirectory: true)
            .appendingPathComponent("gnupg-managed-state.json")
    }

    static var health: IntegrationHealth {
        let wrapper = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport/passeport-scd")
        let conf = gnupgHome().appendingPathComponent("gpg-agent.conf")
        guard let body = try? String(contentsOf: conf, encoding: .utf8), body.contains("scdaemon-program") && body.contains("passeport-scd") else {
            return .notConfigured
        }
        return FileManager.default.isExecutableFile(atPath: wrapper.path)
            ? .working
            : .broken("gpg-agent.conf points at Passeport, but the scdaemon wrapper is missing.")
    }

    static func remove() throws {
        try requireReadableManagedState()
        let conf = gnupgHome().appendingPathComponent("gpg-agent.conf")
        if let body = try? String(contentsOf: conf, encoding: .utf8) {
            let state = loadManagedState()
            var lines = body.components(separatedBy: .newlines)
            var removedManagedScdaemon = false
            if let index = lines.firstIndex(where: {
                let line = $0.trimmingCharacters(in: .whitespaces)
                if let state { return line == state.managedScdaemonLine }
                return line.hasPrefix("scdaemon-program") && line.contains("passeport-scd")
            }) {
                if let previous = state?.previousScdaemonLine { lines[index] = previous }
                else { lines.remove(at: index) }
                removedManagedScdaemon = true
            }
            if removedManagedScdaemon, state?.addedSSHSupport == true,
               let index = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces) == "enable-ssh-support" }) {
                lines.remove(at: index)
            }
            try lines.joined(separator: "\n").write(to: conf, atomically: true, encoding: .utf8)
        }
        try? FileManager.default.removeItem(at: stateURL)
        let wrapper = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport/passeport-scd")
        try? FileManager.default.removeItem(at: wrapper)
        if let gpg = try? locateTool("gpg") {
            let gpgconf = (try? locateTool("gpgconf")) ?? siblingTool(of: gpg, named: "gpgconf")
            _ = try? run(gpgconf, ["--kill", "all"], home: gnupgHome())
        }
    }
    struct Result {
        let gpgPath: String
        let wrapperPath: String
        let agentConfPath: String
        let sshAuthSock: String
        let notes: [String]
    }

    enum ConfigError: LocalizedError {
        case gpgNotFound
        case commandFailed(String, String)
        case corruptManagedState

        var errorDescription: String? {
            switch self {
            case .gpgNotFound:
                "Could not find the gpg binary. Install GnuPG, or set PASSEPORT_GPG to its path."
            case .commandFailed(let tool, let message):
                "\(tool) failed: \(message)"
            case .corruptManagedState:
                "Passeport's saved GnuPG configuration snapshot is corrupt. No GnuPG configuration was changed; restore or remove gnupg-managed-state.json manually before trying again."
            }
        }
    }

    /// Configure GnuPG to use the running bridge for `publicKeyArmored`.
    static func configure(publicKeyArmored: String, socketPath: String, helperPath: String) throws -> Result {
        let gpg = try locateTool("gpg")
        let gpgconf = (try? locateTool("gpgconf")) ?? siblingTool(of: gpg, named: "gpgconf")
        var notes: [String] = []

        let wrapperPath = try writeWrapper(socketPath: socketPath, helperPath: helperPath)
        notes.append("Wrote scdaemon wrapper.")

        let home = gnupgHome()
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let agentConf = home.appendingPathComponent("gpg-agent.conf")
        try configureAgentConf(at: agentConf, wrapperPath: wrapperPath)
        notes.append("Updated gpg-agent.conf.")

        // Restart the agent so the new scdaemon-program takes effect.
        _ = try? run(gpgconf, ["--kill", "all"], home: home)

        // Read the key's own fingerprint and user ID so we can prune any
        // stale user IDs a previous import left behind.
        let keyInfo = try? readKeyInfo(gpg: gpg, home: home, armored: publicKeyArmored)

        try run(gpg, ["--batch", "--import"], home: home, stdin: Data(publicKeyArmored.utf8))
        notes.append("Imported the public key.")

        if let keyInfo, !keyInfo.userID.isEmpty {
            let removed = pruneUserIDs(gpg: gpg, home: home, fingerprint: keyInfo.fingerprint, keep: keyInfo.userID)
            if removed > 0 {
                notes.append("Removed \(removed) stale user ID\(removed == 1 ? "" : "s").")
            }
        }

        // Trigger the agent LEARN that shadows the card keys into stubs.
        let cardStatus = try run(gpg, ["--card-status"], home: home)
        if cardStatus.contains("Passeport") {
            notes.append("Card recognized and key stubs created.")
        } else {
            notes.append("Ran card-status (verify the card appears).")
        }

        let sshSock = (try? run(gpgconf, ["--list-dirs", "agent-ssh-socket"], home: home))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        return Result(
            gpgPath: gpg.path,
            wrapperPath: wrapperPath,
            agentConfPath: agentConf.path,
            sshAuthSock: sshSock,
            notes: notes
        )
    }

    // MARK: - Steps

    private static func writeWrapper(socketPath: String, helperPath: String) throws -> String {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let wrapper = dir.appendingPathComponent("passeport-scd")

        let script = """
        #!/bin/bash
        # Generated by Passeport. Points gpg-agent's scdaemon at the Passeport
        # virtual card served by the running app.
        export PASSEPORT_SCD_SOCKET=\(ShellQuote.quote(socketPath))
        exec \(ShellQuote.quote(helperPath)) scd
        """
        try script.write(to: wrapper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: wrapper.path)
        return wrapper.path
    }

    private static func configureAgentConf(at url: URL, wrapperPath: String) throws {
        try requireReadableManagedState()
        let fm = FileManager.default
        let existing = try? String(contentsOf: url, encoding: .utf8)
        if let existing {
            // Back up once before the first modification.
            let backup = url.appendingPathExtension("passeport-bak")
            if !fm.fileExists(atPath: backup.path) {
                try? existing.write(to: backup, atomically: true, encoding: .utf8)
            }
        }
        if loadManagedState() == nil {
            let lines = existing?.components(separatedBy: .newlines) ?? []
            let previous = lines.first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("scdaemon-program") })
            let hadSSHSupport = lines.contains { $0.trimmingCharacters(in: .whitespaces) == "enable-ssh-support" }
            let state = ManagedState(
                previousScdaemonLine: previous,
                addedSSHSupport: !hadSSHSupport,
                managedScdaemonLine: "scdaemon-program \(wrapperPath)"
            )
            try FileManager.default.createDirectory(at: stateURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(state).write(to: stateURL, options: .atomic)
        }
        let body = agentConfBody(existing: existing, wrapperPath: wrapperPath)
        try body.write(to: url, atomically: true, encoding: .utf8)
    }

    private static func loadManagedState() -> ManagedState? {
        guard let data = try? Data(contentsOf: stateURL) else { return nil }
        return try? JSONDecoder().decode(ManagedState.self, from: data)
    }

    static func managedStateDataIsValid(_ data: Data) -> Bool {
        (try? JSONDecoder().decode(ManagedState.self, from: data)) != nil
    }

    private static func requireReadableManagedState() throws {
        guard FileManager.default.fileExists(atPath: stateURL.path) else { return }
        guard let data = try? Data(contentsOf: stateURL), managedStateDataIsValid(data) else {
            throw ConfigError.corruptManagedState
        }
    }

    /// Pure transform: given the current gpg-agent.conf (if any), return the
    /// content with exactly one `scdaemon-program` line pointing at our
    /// wrapper and `enable-ssh-support` present. Idempotent.
    static func agentConfBody(existing: String?, wrapperPath: String) -> String {
        var lines = existing?.components(separatedBy: .newlines) ?? []
        // Drop trailing blank lines so repeated runs don't accumulate them.
        while let last = lines.last, last.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.removeLast()
        }
        // Replace an existing scdaemon-program line in place (stable order),
        // otherwise append it.
        let scdLine = "scdaemon-program \(wrapperPath)"
        if let index = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces).hasPrefix("scdaemon-program")
        }) {
            lines[index] = scdLine
        } else {
            lines.append(scdLine)
        }
        if !lines.contains(where: { $0.trimmingCharacters(in: .whitespaces) == "enable-ssh-support" }) {
            lines.append("enable-ssh-support")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Public path to the discovered gpg, for callers like git config.
    static func gpgPath() throws -> String {
        try locateTool("gpg").path
    }

    /// Passeport's OpenPGP card AID prefix (RID + app + version + the 0xFFFE
    /// test-range manufacturer), as it appears in gpg's stub serial numbers.
    private static let cardSerialPrefix = "D276000124010304FFFE"

    /// True when gpg holds card stubs for a Passeport card but none of them
    /// match the current identity — the stubs reference an older seed and
    /// "Configure GnuPG" needs to be re-run. False when gpg is missing or has
    /// no Passeport stubs at all (nothing configured, nothing stale).
    static func hasStaleCardStubs(currentFingerprint: String) -> Bool {
        guard let gpg = try? locateTool("gpg"),
              let output = try? run(gpg, ["-K", "--with-colons"], home: gnupgHome()) else {
            return false
        }
        var passeportPrimaryFingerprints: [String] = []
        var awaitingFingerprint = false
        for line in output.split(separator: "\n") {
            let fields = line.components(separatedBy: ":")
            guard let record = fields.first else { continue }
            switch record {
            case "sec":
                awaitingFingerprint = fields.count > 14 && fields[14].hasPrefix(cardSerialPrefix)
            case "fpr" where awaitingFingerprint:
                if fields.count > 9 {
                    passeportPrimaryFingerprints.append(fields[9].uppercased())
                }
                awaitingFingerprint = false
            default:
                break
            }
        }
        guard !passeportPrimaryFingerprints.isEmpty else { return false }
        return !passeportPrimaryFingerprints.contains(currentFingerprint.uppercased())
    }

    // MARK: - User-ID pruning

    private struct KeyInfo {
        let fingerprint: String
        let userID: String
    }

    /// Read a key's fingerprint and primary user ID without importing it.
    private static func readKeyInfo(gpg: URL, home: URL, armored: String) throws -> KeyInfo {
        let output = try run(gpg, ["--show-keys", "--with-colons"], home: home, stdin: Data(armored.utf8))
        var fingerprint = ""
        var userID = ""
        for line in output.split(separator: "\n") {
            let fields = line.components(separatedBy: ":")
            guard fields.count > 9 else { continue }
            if fields[0] == "fpr", fingerprint.isEmpty {
                fingerprint = fields[9]
            } else if fields[0] == "uid", userID.isEmpty {
                userID = unescapeColons(fields[9])
            }
        }
        return KeyInfo(fingerprint: fingerprint, userID: userID)
    }

    /// Delete every user ID on `fingerprint` except `keep`, so re-importing
    /// after a user-ID change doesn't leave stale labels. Returns how many
    /// were removed. Never removes the kept ID, and only acts when it is
    /// actually present (guarding against leaving the key with no user IDs).
    @discardableResult
    private static func pruneUserIDs(gpg: URL, home: URL, fingerprint: String, keep: String) -> Int {
        var removed = 0
        // Each pass removes at most one ID; bound the loop defensively.
        for _ in 0..<16 {
            let uids = listUserIDs(gpg: gpg, home: home, fingerprint: fingerprint)
            guard let staleIndex = firstStaleUserIDIndex(uids: uids, keep: keep) else {
                break
            }
            let commands = "uid \(staleIndex + 1)\ndeluid\ny\nsave\n"
            do {
                try run(
                    gpg,
                    ["--no-tty", "--command-fd", "0", "--status-fd", "2", "--edit-key", fingerprint],
                    home: home,
                    stdin: Data(commands.utf8)
                )
                removed += 1
            } catch {
                break
            }
        }
        return removed
    }

    /// Pure: index of the first user ID to prune, or nil if none should be.
    /// Only acts when the kept ID is present and there is more than one ID, so
    /// it can never leave the key with zero user IDs or delete the kept one.
    static func firstStaleUserIDIndex(uids: [String], keep: String) -> Int? {
        guard uids.count > 1, uids.contains(keep) else { return nil }
        return uids.firstIndex(where: { $0 != keep })
    }

    private static func listUserIDs(gpg: URL, home: URL, fingerprint: String) -> [String] {
        guard let output = try? run(gpg, ["--with-colons", "--list-keys", fingerprint], home: home) else {
            return []
        }
        return output.split(separator: "\n").compactMap { line -> String? in
            let fields = line.components(separatedBy: ":")
            guard fields.count > 9, fields[0] == "uid" else { return nil }
            return unescapeColons(fields[9])
        }
    }

    /// gpg `--with-colons` C-escapes colons and backslashes in text fields.
    private static func unescapeColons(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\x3a", with: ":")
            .replacingOccurrences(of: "\\x5c", with: "\\")
    }

    // MARK: - Tool discovery

    private static func locateTool(_ name: String) throws -> URL {
        if name == "gpg", let override = ProcessInfo.processInfo.environment["PASSEPORT_GPG"],
           !override.isEmpty, FileManager.default.isExecutableFile(atPath: override) {
            return URL(fileURLWithPath: override)
        }
        let searchDirs = [
            "\(NSHomeDirectory())/.grimoire/profiles/current/bin",
            "\(NSHomeDirectory())/.local/bin",
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
        ]
        for dir in searchDirs {
            let candidate = "\(dir)/\(name)"
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return URL(fileURLWithPath: candidate)
            }
        }
        if name == "gpg" {
            throw ConfigError.gpgNotFound
        }
        throw ConfigError.commandFailed(name, "not found")
    }

    private static func siblingTool(of tool: URL, named name: String) -> URL {
        tool.deletingLastPathComponent().appendingPathComponent(name)
    }

    private static func gnupgHome() -> URL {
        if let home = ProcessInfo.processInfo.environment["GNUPGHOME"], !home.isEmpty {
            return URL(fileURLWithPath: home)
        }
        return URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".gnupg", isDirectory: true)
    }

    // MARK: - Process helper

    @discardableResult
    private static func run(_ tool: URL, _ args: [String], home: URL, stdin: Data? = nil) throws -> String {
        let process = Process()
        process.executableURL = tool
        process.arguments = args
        var environment = ProcessInfo.processInfo.environment
        environment["GNUPGHOME"] = home.path
        process.environment = environment

        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        if stdin != nil {
            let inPipe = Pipe()
            process.standardInput = inPipe
            try process.run()
            inPipe.fileHandleForWriting.write(stdin!)
            try inPipe.fileHandleForWriting.close()
        } else {
            try process.run()
        }

        let output = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errorOut = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let message = String(data: errorOut, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? "exit \(process.terminationStatus)"
            throw ConfigError.commandFailed(tool.lastPathComponent, message)
        }
        // gpg writes useful text to stderr; fold both together for callers.
        let combined = (String(data: output, encoding: .utf8) ?? "")
            + (String(data: errorOut, encoding: .utf8) ?? "")
        return combined
    }
}
