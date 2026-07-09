import Foundation

/// Configures git to sign commits and tags with the Passeport identity, either
/// through GnuPG (OpenPGP signatures) or SSH (`gpg.format=ssh`, signed via the
/// native agent) — the two toolchains Passeport supports.
enum GitConfigurator {
    struct Result {
        let gitPath: String
        let signingKey: String
    }

    struct SSHSigningResult {
        let gitPath: String
        let publicKeyPath: String
        let allowedSignersPath: String
        let sshAuthSock: String
    }

    enum GitError: LocalizedError {
        case gitNotFound
        case commandFailed(String)

        var errorDescription: String? {
            switch self {
            case .gitNotFound:
                "Could not find the git binary. Install git or the Xcode command line tools."
            case .commandFailed(let message):
                "git config failed: \(message)"
            }
        }
    }

    /// Set global git config to sign with `fingerprint` using `gpgPath`.
    static func configure(fingerprint: String, gpgPath: String) throws -> Result {
        let git = try locateGit()
        let settings = [
            ("gpg.program", gpgPath),
            ("user.signingkey", fingerprint),
            ("commit.gpgsign", "true"),
            ("tag.gpgsign", "true"),
        ]
        for (key, value) in settings {
            try run(git, ["config", "--global", key, value])
        }
        return Result(gitPath: git.path, signingKey: fingerprint)
    }

    /// Configure git to sign commits/tags with an SSH key (`gpg.format=ssh`).
    /// The private key never leaves Passeport: `ssh-keygen -Y sign` reaches it
    /// through the native agent at `sshAuthSock`. Also writes an
    /// `allowed_signers` file so `git log --show-signature` verifies locally.
    static func configureSSHSigning(publicKey: String, sshAuthSock: String) throws -> SSHSigningResult {
        let git = try locateGit()
        let sshKeygen = locateSSHKeygen()

        let signerPrincipal = configuredEmail(git: git) ?? "passeport"
        let normalizedKey = publicKey.trimmingCharacters(in: .whitespacesAndNewlines)

        let sshDir = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".ssh", isDirectory: true)
        try FileManager.default.createDirectory(
            at: sshDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        // Public key file that user.signingkey points at.
        let pubPath = sshDir.appendingPathComponent("passeport-signing.pub")
        try (normalizedKey + "\n").write(to: pubPath, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pubPath.path)

        // allowed_signers is a Passeport-managed file (only ever this one
        // principal), so overwriting it can't clobber a user's other signers.
        let allowedPath = sshDir.appendingPathComponent("passeport_allowed_signers")
        let allowedLine = "\(signerPrincipal) namespaces=\"git\" \(normalizedKey)\n"
        try allowedLine.write(to: allowedPath, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: allowedPath.path)

        var settings = [
            ("gpg.format", "ssh"),
            ("user.signingkey", pubPath.path),
            ("commit.gpgsign", "true"),
            ("tag.gpgsign", "true"),
            ("gpg.ssh.allowedSignersFile", allowedPath.path),
        ]
        if let sshKeygen {
            settings.append(("gpg.ssh.program", sshKeygen.path))
        }
        for (key, value) in settings {
            try run(git, ["config", "--global", key, value])
        }

        return SSHSigningResult(
            gitPath: git.path,
            publicKeyPath: pubPath.path,
            allowedSignersPath: allowedPath.path,
            sshAuthSock: sshAuthSock
        )
    }

    /// The globally configured git author email, used as the SSH signer
    /// principal. Nil when unset.
    private static func configuredEmail(git: URL) -> String? {
        let email = (try? run(git, ["config", "--global", "user.email"]))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (email?.isEmpty == false) ? email : nil
    }

    private static func locateSSHKeygen() -> URL? {
        let candidates = ["/usr/bin/ssh-keygen", "/opt/homebrew/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"]
        return candidates
            .first { FileManager.default.isExecutableFile(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
    }

    private static func locateGit() throws -> URL {
        let candidates = [
            "/usr/bin/git",
            "/opt/homebrew/bin/git",
            "/usr/local/bin/git",
            "\(NSHomeDirectory())/.grimoire/profiles/current/bin/git",
        ]
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return URL(fileURLWithPath: path)
        }
        throw GitError.gitNotFound
    }

    @discardableResult
    private static func run(_ tool: URL, _ args: [String]) throws -> String {
        let process = Process()
        process.executableURL = tool
        process.arguments = args
        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        let output = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errorOut = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(data: errorOut, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? "exit \(process.terminationStatus)"
            throw GitError.commandFailed(message)
        }
        return String(data: output, encoding: .utf8) ?? ""
    }
}
