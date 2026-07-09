import Foundation

extension Notification.Name {
    static let passeportAuditLogDidChange = Notification.Name("PasseportAuditLogDidChange")
}

struct OperationAuditEvent: Codable, Identifiable {
    let id: UUID
    let timestamp: Date
    let kind: String
    let keyref: String
    let requestingClient: String
    let byteCount: Int
    let summary: String
    let details: String
    let outcome: String
}

/// Append-only local operation log.
actor OperationAuditLog {
    static let shared = OperationAuditLog()
    static let maxEntries = 500

    private var cached: [OperationAuditEvent] = []

    private static var fileURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport", isDirectory: true)
        return base.appendingPathComponent("operation-audit.json")
    }

    func events(limit: Int = maxEntries) async -> [OperationAuditEvent] {
        if cached.isEmpty {
            cached = loadOrQuarantine()
        }
        return Array(cached.prefix(limit))
    }

    func append(event: OperationAuditEvent) async {
        var current = cached
        if current.isEmpty {
            current = loadOrQuarantine()
        }
        current.insert(event, at: 0)
        if current.count > Self.maxEntries {
            current = Array(current.prefix(Self.maxEntries))
        }
        cached = current
        _ = try? save(current)
        await notifyChanged()
    }

    func clear() async {
        cached.removeAll()
        try? FileManager.default.removeItem(at: Self.fileURL)
        await notifyChanged()
    }

    /// Read the log from disk. A missing file is a fresh log; an unreadable
    /// one is moved aside instead of being silently overwritten by the next
    /// append — this is an audit trail, losing it should leave a trace.
    private func loadOrQuarantine() -> [OperationAuditEvent] {
        guard let data = try? Data(contentsOf: Self.fileURL) else {
            return []
        }
        do {
            return try JSONDecoder().decode([OperationAuditEvent].self, from: data)
        } catch {
            let quarantine = Self.fileURL.appendingPathExtension("corrupt")
            try? FileManager.default.removeItem(at: quarantine)
            try? FileManager.default.moveItem(at: Self.fileURL, to: quarantine)
            return []
        }
    }

    private func save(_ events: [OperationAuditEvent]) throws {
        let base = Self.fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: base.path) {
            try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        }
        let encoded = try JSONEncoder().encode(events)
        try encoded.write(to: Self.fileURL)
    }

    private func notifyChanged() async {
        await MainActor.run {
            NotificationCenter.default.post(name: .passeportAuditLogDidChange, object: nil)
        }
    }
}
