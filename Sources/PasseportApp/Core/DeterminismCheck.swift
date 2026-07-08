import Foundation

/// Runs the helper's `selftest` mode, which re-derives from a fixed test PRF
/// and asserts the fingerprint matches a frozen baseline. Catches the day a
/// dependency change silently alters derivation output.
enum DeterminismCheck {
    enum Outcome {
        case passed
        case failed(String)
    }

    static func run() -> Outcome {
        let helperURL: URL
        do {
            helperURL = try CoreLocator.helperURL()
        } catch {
            return .failed("Key helper not found for the derivation self-test.")
        }

        let process = Process()
        process.executableURL = helperURL
        process.arguments = ["selftest"]
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
        } catch {
            return .failed("Could not run the derivation self-test: \(error.localizedDescription)")
        }
        let errorData = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        if process.terminationStatus == 0 {
            return .passed
        }
        let message = String(data: errorData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return .failed(
            message?.isEmpty == false
                ? "Derivation self-test failed: \(message!)"
                : "Derivation self-test failed — the identity may no longer match other devices."
        )
    }
}
