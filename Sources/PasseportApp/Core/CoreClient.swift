import Foundation

struct CoreClient {
    struct DeriveRequest: Encodable {
        let prf: String
        let user_id: String
        let ssh_comment: String
    }

    func derive(prf: Data, userID: String, sshComment: String) async throws -> DerivedIdentity {
        let helperURL = try CoreLocator.helperURL()
        let request = DeriveRequest(
            prf: prf.base64URLEncodedString(),
            user_id: userID,
            ssh_comment: sshComment
        )
        let input = try JSONEncoder().encode(request)

        return try await Task.detached(priority: .userInitiated) {
            try runHelper(helperURL: helperURL, input: input)
        }.value
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private func runHelper(helperURL: URL, input: Data) throws -> DerivedIdentity {
    let process = Process()
    process.executableURL = helperURL

    let stdin = Pipe()
    let stdout = Pipe()
    let stderr = Pipe()
    process.standardInput = stdin
    process.standardOutput = stdout
    process.standardError = stderr

    try process.run()
    stdin.fileHandleForWriting.write(input)
    try stdin.fileHandleForWriting.close()
    process.waitUntilExit()

    let output = stdout.fileHandleForReading.readDataToEndOfFile()
    let errorOutput = stderr.fileHandleForReading.readDataToEndOfFile()

    guard process.terminationStatus == 0 else {
        let message = String(data: errorOutput, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        throw PasseportError.helperFailed(message?.isEmpty == false ? message! : "key helper failed")
    }

    do {
        return try JSONDecoder().decode(DerivedIdentity.self, from: output)
    } catch {
        throw PasseportError.helperFailed("key helper returned invalid JSON: \(error.localizedDescription)")
    }
}
