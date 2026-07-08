import Foundation

/// Bridges the seed backup/recovery CLI modes of the Rust helper:
/// `mnemonic-encode`, `mnemonic-decode`, and `revoke`.
enum SeedBackup {
    /// 24-word BIP39 recovery phrase for the raw root seed.
    static func recoveryPhrase(seed: Data) throws -> String {
        let response = try runHelperJSON(
            arguments: ["mnemonic-encode"],
            input: ["seed": seed.base64URLEncodedString()]
        )
        guard let mnemonic = response["mnemonic"] as? String else {
            throw PasseportError.helperFailed("helper did not return a mnemonic")
        }
        return mnemonic
    }

    /// Recover the raw 32-byte root seed from a recovery phrase.
    static func seed(fromPhrase phrase: String) throws -> Data {
        let response = try runHelperJSON(
            arguments: ["mnemonic-decode"],
            input: ["mnemonic": phrase]
        )
        guard let encoded = response["seed"] as? String,
              let seed = try? Data(base64URL: encoded), seed.count == 32 else {
            throw PasseportError.helperFailed("helper did not return a valid seed")
        }
        return seed
    }

    /// Armored OpenPGP revocation certificate for the identity `prf` derives.
    static func revocationCertificate(prf: Data, userID: String) throws -> String {
        let output = try runHelper(
            arguments: ["revoke"],
            input: try JSONSerialization.data(withJSONObject: [
                "prf": prf.base64URLEncodedString(),
                "user_id": userID
            ])
        )
        guard let text = String(data: output, encoding: .utf8),
              text.contains("BEGIN PGP") else {
            throw PasseportError.helperFailed("helper did not return a revocation certificate")
        }
        return text
    }

    // MARK: - Process plumbing

    private static func runHelperJSON(arguments: [String], input: [String: Any]) throws -> [String: Any] {
        let data = try JSONSerialization.data(withJSONObject: input)
        let output = try runHelper(arguments: arguments, input: data)
        guard let object = try JSONSerialization.jsonObject(with: output) as? [String: Any] else {
            throw PasseportError.helperFailed("helper returned invalid JSON")
        }
        return object
    }

    private static func runHelper(arguments: [String], input: Data) throws -> Data {
        let helperURL = try CoreLocator.helperURL()
        let process = Process()
        process.executableURL = helperURL
        process.arguments = arguments
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorOut = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let message = String(data: errorOut, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw PasseportError.helperFailed(
                message?.isEmpty == false ? message! : "helper \(arguments.first ?? "") failed"
            )
        }
        return output
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init(base64URL string: String) throws {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = base64.count % 4
        if padding > 0 {
            base64.append(String(repeating: "=", count: 4 - padding))
        }
        guard let data = Data(base64Encoded: base64) else {
            throw PasseportError.helperFailed("invalid base64url data")
        }
        self = data
    }
}
