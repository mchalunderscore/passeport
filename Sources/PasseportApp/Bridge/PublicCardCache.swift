import Foundation

/// Disk cache of the bridge's `pubkeys` response: public key points and
/// fingerprints only, never secret material.
///
/// gpg models the virtual card by asking for this metadata often — including
/// right after launchd socket-activates the app in the background. Serving it
/// from cache means those lookups need no seed unlock (no Touch ID prompt);
/// only actual sign/decrypt operations touch the seed.
enum PublicCardCache {
    private static var fileURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport", isDirectory: true)
            .appendingPathComponent("public-card.json")
    }

    /// The cached response line, or `nil` if none has been stored yet.
    static func load() -> String? {
        guard let data = try? Data(contentsOf: fileURL),
              let line = String(data: data, encoding: .utf8)?
                  .trimmingCharacters(in: .whitespacesAndNewlines),
              isValidResponse(line) else {
            return nil
        }
        return line
    }

    /// The raw 32-byte public key for the slot with the given role, parsed
    /// out of a `pubkeys` response line: finds the slot, validates the
    /// 0x40-prefixed 33-byte compressed point, and strips the prefix.
    static func publicKey(role: String, inResponseLine line: String?) -> Data? {
        guard let line,
              let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
              object["ok"] as? Bool == true,
              let slots = object["slots"] as? [[String: Any]],
              let slot = slots.first(where: { ($0["role"] as? String) == role }),
              let qHex = slot["q"] as? String,
              let q = Hex.decode(qHex),
              q.count == 33, q.first == 0x40 else {
            return nil
        }
        return Data(q.dropFirst())
    }

    /// Persist a `pubkeys` response line; ignores anything but a well-formed
    /// success response so an error never gets replayed to clients.
    static func store(_ responseLine: String) {
        let line = responseLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidResponse(line) else { return }
        let directory = fileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? Data(line.utf8).write(to: fileURL, options: .atomic)
    }

    static func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }

    private static func isValidResponse(_ line: String) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
            return false
        }
        return object["ok"] as? Bool == true && object["slots"] is [[String: Any]]
    }
}
