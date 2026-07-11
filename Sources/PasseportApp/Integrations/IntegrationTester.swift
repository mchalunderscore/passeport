import Foundation

/// Exercises configured integrations through their public command-line surface.
/// Every test uses an isolated temporary directory and performs a real private
/// operation followed by public verification (or decryption), so a green result
/// means more than "the wrapper file exists".
enum IntegrationTester {
    enum TestError: LocalizedError {
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .failed(let message): message
            }
        }
    }

    static func run(
        _ integration: PasseportIntegration,
        identity: DerivedIdentity,
        sshSocketPath: String
    ) throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("passeport-integration-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let message = directory.appendingPathComponent("message.txt")
        try Data("Passeport integration test\n".utf8).write(to: message, options: .atomic)

        switch integration {
        case .ssh:
            try testSSH(message: message, directory: directory, publicKey: identity.ssh.publicKey, socket: sshSocketPath)
            return "SSH signing and verification passed"
        case .openpgpBundled:
            let command = managedCommand("passeport-gpg", directory: "openpgp-mode2")
            try testOpenPGP(command: command, message: message, directory: directory, fingerprint: identity.pgp.fingerprint)
            return "Bundled OpenPGP signing and verification passed"
        case .openpgpScdaemon:
            guard let command = ToolingInstaller.gnuPGPath else { throw TestError.failed("GnuPG is not available.") }
            try testOpenPGP(command: URL(fileURLWithPath: command), message: message, directory: directory, fingerprint: identity.pgp.fingerprint)
            return "Pluggable OpenPGP signing and verification passed"
        case .git:
            try testGit(directory: directory)
            return "Git created and verified a signed commit"
        case .age:
            try testAge(message: message, directory: directory, recipient: identity.age.recipient)
            return "age encryption and decryption passed"
        case .minisign:
            try testMinisign(message: message, directory: directory)
            return "minisign signing and verification passed"
        }
    }

    private static func testSSH(message: URL, directory: URL, publicKey: String, socket: String) throws {
        let key = directory.appendingPathComponent("passeport.pub")
        let allowed = directory.appendingPathComponent("allowed_signers")
        try (publicKey.trimmingCharacters(in: .whitespacesAndNewlines) + "\n").write(to: key, atomically: true, encoding: .utf8)
        try ("passeport namespaces=\"passeport-test\" \(publicKey.trimmingCharacters(in: .whitespacesAndNewlines))\n")
            .write(to: allowed, atomically: true, encoding: .utf8)
        try run(URL(fileURLWithPath: "/usr/bin/ssh-keygen"), ["-Y", "sign", "-f", key.path, "-n", "passeport-test", message.path], environment: ["SSH_AUTH_SOCK": socket])
        let signature = URL(fileURLWithPath: message.path + ".sig")
        let signatureData = try Data(contentsOf: signature)
        try run(URL(fileURLWithPath: "/usr/bin/ssh-keygen"), ["-Y", "verify", "-f", allowed.path, "-I", "passeport", "-n", "passeport-test", "-s", signature.path], stdin: try Data(contentsOf: message))
        guard !signatureData.isEmpty else { throw TestError.failed("SSH produced an empty signature.") }
    }

    private static func testOpenPGP(command: URL, message: URL, directory: URL, fingerprint: String) throws {
        let signature = directory.appendingPathComponent("message.asc")
        try run(command, ["--batch", "--yes", "--armor", "--local-user", fingerprint, "--output", signature.path, "--detach-sign", message.path])
        try run(command, ["--batch", "--verify", signature.path, message.path])
    }

    private static func testAge(message: URL, directory: URL, recipient: String) throws {
        let command = managedCommand("passeport-age", directory: "age")
        let encrypted = directory.appendingPathComponent("message.age")
        let decrypted = directory.appendingPathComponent("message.decrypted")
        try run(command, ["-e", "-r", recipient, "-o", encrypted.path, message.path])
        try run(command, ["-d", "-o", decrypted.path, encrypted.path])
        guard try Data(contentsOf: decrypted) == Data(contentsOf: message) else {
            throw TestError.failed("age decrypted different contents than it encrypted.")
        }
    }

    private static func testMinisign(message: URL, directory: URL) throws {
        let command = managedCommand("passeport-minisign", directory: "minisign")
        let signature = directory.appendingPathComponent("message.minisig")
        let publicKey = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".minisign/passeport.pub")
        try run(command, ["-S", "-m", message.path, "-x", signature.path])
        try run(command, ["-V", "-m", message.path, "-x", signature.path, "-p", publicKey.path])
    }

    private static func testGit(directory: URL) throws {
        let git = URL(fileURLWithPath: "/usr/bin/git")
        try run(git, ["init", "--quiet", directory.path])
        try run(git, ["-C", directory.path, "config", "user.name", "Passeport Test"])
        try run(git, ["-C", directory.path, "config", "user.email", "passeport-test@localhost"])
        let file = directory.appendingPathComponent("commit.txt")
        try "Passeport Git integration test\n".write(to: file, atomically: true, encoding: .utf8)
        try run(git, ["-C", directory.path, "add", "commit.txt"])
        try run(git, ["-C", directory.path, "commit", "--quiet", "-S", "-m", "Passeport integration test"])
        try run(git, ["-C", directory.path, "verify-commit", "HEAD"])
    }

    private static func managedCommand(_ name: String, directory: String) -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport/\(directory)/\(name)")
    }

    @discardableResult
    private static func run(
        _ command: URL,
        _ arguments: [String],
        environment: [String: String] = [:],
        stdin: Data? = nil
    ) throws -> Data {
        let process = Process()
        process.executableURL = command
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, replacement in replacement }
        let output = Pipe()
        let input = Pipe()
        process.standardOutput = output
        process.standardError = output
        process.standardInput = input
        try process.run()
        if let stdin { input.fileHandleForWriting.write(stdin) }
        try input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            throw TestError.failed(detail?.isEmpty == false ? detail! : "\(command.lastPathComponent) exited with status \(process.terminationStatus).")
        }
        return data
    }
}
