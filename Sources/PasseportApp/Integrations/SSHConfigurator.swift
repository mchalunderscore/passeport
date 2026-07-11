import Foundation

/// One-shot SSH setup: points `~/.ssh/config` at the native Passeport agent
/// via `IdentityAgent`, so ssh uses it without shell-profile changes.
/// The existing config is backed up before the first modification and edits
/// are idempotent.
enum SSHConfigurator {
    struct Result {
        let configPath: String
        let socketPath: String
    }

    private static let marker = "# Passeport ssh agent — managed block"

    static func configure(socketPath: String) throws -> Result {
        let fm = FileManager.default
        let sshDir = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".ssh", isDirectory: true)
        try fm.createDirectory(
            at: sshDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let config = sshDir.appendingPathComponent("config")
        let existing = try? String(contentsOf: config, encoding: .utf8)
        if let existing {
            // Back up once before the first modification.
            let backup = config.appendingPathExtension("passeport-bak")
            if !fm.fileExists(atPath: backup.path) {
                try? existing.write(to: backup, atomically: true, encoding: .utf8)
            }
        }
        let body = configBody(existing: existing, socketPath: socketPath)
        try body.write(to: config, atomically: true, encoding: .utf8)
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: config.path)
        return Result(configPath: config.path, socketPath: socketPath)
    }

    /// Pure transform: given the current ssh config (if any), return it with
    /// exactly one Passeport IdentityAgent block appended. Appending keeps any
    /// user-defined IdentityAgent for specific hosts winning (first value
    /// obtained per option is used by ssh). Idempotent.
    static func configBody(existing: String?, socketPath: String) -> String {
        var lines = existing?.components(separatedBy: .newlines) ?? []
        // Remove a previous Passeport block: the marker plus its two lines.
        if let index = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces) == marker }) {
            let end = min(index + 3, lines.count)
            lines.removeSubrange(index..<end)
        }
        while let last = lines.last, last.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.removeLast()
        }
        let block = """
        \(marker)
        Host *
          IdentityAgent "\(socketPath)"
        """
        let head = lines.joined(separator: "\n")
        return (head.isEmpty ? "" : head + "\n\n") + block + "\n"
    }

    static var health: IntegrationHealth {
        let config = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".ssh/config")
        guard let body = try? String(contentsOf: config, encoding: .utf8), body.contains(marker) else {
            return .notConfigured
        }
        return body.contains(SSHAgentServer.socketURL.path) ? .working : .broken("The SSH config points at an outdated Passeport socket.")
    }

    static func remove() throws {
        let config = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".ssh/config")
        guard let existing = try? String(contentsOf: config, encoding: .utf8) else { return }
        var lines = existing.components(separatedBy: .newlines)
        if let index = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces) == marker }) {
            lines.removeSubrange(index..<min(index + 3, lines.count))
            while lines.last?.trimmingCharacters(in: .whitespaces).isEmpty == true { lines.removeLast() }
            try (lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n")).write(to: config, atomically: true, encoding: .utf8)
        }
    }
}
