import Foundation

/// Configures git to sign commits and tags with the Passeport OpenPGP key
/// (via the same gpg the smartcard bridge uses).
enum GitConfigurator {
    struct Result {
        let gitPath: String
        let signingKey: String
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

    private static func run(_ tool: URL, _ args: [String]) throws {
        let process = Process()
        process.executableURL = tool
        process.arguments = args
        let errPipe = Pipe()
        process.standardError = errPipe
        try process.run()
        let errorOut = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(data: errorOut, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? "exit \(process.terminationStatus)"
            throw GitError.commandFailed(message)
        }
    }
}
