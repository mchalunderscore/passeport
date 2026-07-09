import AppKit
import Foundation

/// Unix-socket server that answers the scd shim's private-operation requests.
///
/// The shim (`passeport-core scd`, launched by gpg-agent) holds no key
/// material; it connects here per operation. This bridge unlocks the seed
/// behind Touch ID (once per session, via `SeedStore.prf`), then runs the
/// requested Ed25519 sign / X25519 ECDH by shelling `passeport-core op` with
/// the PRF supplied on stdin. The PRF never reaches the shim, only per-op
/// results do.
///
/// The socket path (see `socketURL`) is where the "Configure GnuPG" step
/// points `scdaemon-program`.
@SeedStoreActor
final class ScdBridge {
    static let shared = ScdBridge()

    private var listenerFD: Int32 = -1
    private var accepting = false
    private let userIDProvider: () -> String

    /// When set, each sign/decrypt operation must be approved in a dialog that
    /// shows what is being signed — a defense against a compromised gpg-agent
    /// quietly using the key.
    private var confirmEachOperation = false
    /// When set, Touch ID is re-requested for every operation rather than once
    /// per session.
    private var requireTouchIDPerOperation = false

    private init(userIDProvider: @escaping () -> String = { "Passeport <passeport@localhost>" }) {
        self.userIDProvider = userIDProvider
    }

    func setPolicy(confirmEachOperation: Bool, requireTouchIDPerOperation: Bool) {
        self.confirmEachOperation = confirmEachOperation
        self.requireTouchIDPerOperation = requireTouchIDPerOperation
    }

    nonisolated static var socketURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base
            .appendingPathComponent("Passeport", isDirectory: true)
            .appendingPathComponent("scd.sock")
    }

    var isRunning: Bool { listenerFD >= 0 }

    func start() throws {
        guard listenerFD < 0 else { return }

        // If launchd started us via socket activation, adopt its listening
        // socket instead of binding our own.
        if let inherited = Self.adoptLaunchdSocket() {
            listenerFD = inherited
            accepting = true
            acceptLoop(fd: inherited)
            return
        }

        let url = Self.socketURL
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let path = url.path
        // Unix socket paths are limited to 104 bytes on Darwin.
        guard path.utf8.count < 104 else {
            throw PasseportError.bridgeFailed("socket path too long: \(path)")
        }
        unlink(path)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw PasseportError.bridgeFailed("socket() failed: \(errno)")
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { pointer in
            path.withCString { cString in
                strncpy(UnsafeMutableRawPointer(pointer).assumingMemoryBound(to: CChar.self), cString, 103)
            }
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                bind(fd, sockaddrPointer, size)
            }
        }
        guard bound == 0 else {
            close(fd)
            if errno == EADDRINUSE {
                throw PasseportError.bridgeFailed(
                    "the socket is already in use — the background launcher may already be serving it"
                )
            }
            throw PasseportError.bridgeFailed("bind() failed: \(errno)")
        }
        // Only this user may connect.
        chmod(path, 0o600)
        guard listen(fd, 8) == 0 else {
            close(fd)
            throw PasseportError.bridgeFailed("listen() failed: \(errno)")
        }

        listenerFD = fd
        accepting = true
        acceptLoop(fd: fd)
    }

    func stop() {
        accepting = false
        if listenerFD >= 0 {
            close(listenerFD)
            listenerFD = -1
        }
        unlink(Self.socketURL.path)
    }

    /// The launchd socket name in the LaunchAgent plist's `Sockets` dict.
    nonisolated static let launchdSocketName = "Passeport"

    /// If launchd started this process for socket activation, return the
    /// inherited listening fd. Uses `launch_activate_socket`, resolved with
    /// dlsym so no bridging header is needed.
    private static func adoptLaunchdSocket() -> Int32? {
        typealias ActivateFn = @convention(c) (
            UnsafePointer<CChar>?,
            UnsafeMutablePointer<UnsafeMutablePointer<Int32>?>?,
            UnsafeMutablePointer<Int>?
        ) -> Int32
        // RTLD_DEFAULT searches every loaded image.
        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
        guard let symbol = dlsym(rtldDefault, "launch_activate_socket") else { return nil }
        let activate = unsafeBitCast(symbol, to: ActivateFn.self)

        var fds: UnsafeMutablePointer<Int32>?
        var count = 0
        let result = launchdSocketName.withCString { activate($0, &fds, &count) }
        guard result == 0, let fds, count > 0 else {
            if let fds { free(fds) }
            return nil
        }
        let fd = fds[0]
        free(fds)
        return fd
    }

    private func acceptLoop(fd: Int32) {
        Task.detached(priority: .utility) {
            while await self.accepting {
                let client = accept(fd, nil, nil)
                if client < 0 {
                    if await self.accepting { continue }
                    break
                }
                await self.handle(client: client)
            }
        }
    }

    private func handle(client: Int32) async {
        defer { close(client) }
        guard let requestLine = Self.readLine(fd: client) else { return }
        let responseLine = await process(requestLine: requestLine)
        Self.writeAll(fd: client, string: responseLine + "\n")
    }

    /// Run one private-operation request through the full pipeline —
    /// approval prompt, Touch ID policy, helper invocation, audit log — and
    /// return the response line. Shared by the scd socket and the native
    /// SSH agent, so every key use funnels through the same controls.
    func process(requestLine: String) async -> String {
        guard let parsed = OperationRequestMetadata.parse(requestLine: requestLine) else {
            return Self.errorJSON("invalid operation request")
        }
        let operation = parsed.kind.rawValue
        let keyref = parsed.keyref
        let clientID = parsed.requestingClient
        let byteCount = parsed.byteCount
        let summary = parsed.summary

        if parsed.kind == .unknown {
            await logAuditEvent(
                kind: operation,
                keyref: keyref,
                requestingClient: clientID,
                byteCount: byteCount,
                summary: summary,
                outcome: "failed",
                detail: "unsupported operation"
            )
            return Self.errorJSON("unsupported operation")
        }

        // Public card metadata is not secret: serve it from the cache without
        // unlocking the seed or asking for approval, so routine gpg lookups
        // never pop Touch ID.
        if parsed.kind == .keyLookup, let cached = PublicCardCache.load() {
            await logAuditEvent(
                kind: operation,
                keyref: keyref,
                requestingClient: clientID,
                byteCount: byteCount,
                summary: summary,
                outcome: "succeeded",
                detail: "served from public key cache without unlocking the seed"
            )
            return cached
        }

        let responseLine: String
        do {
            if confirmEachOperation {
                let approved = await Self.confirm(prompt: parsed.toApprovalPrompt())
                guard approved else {
                    await logAuditEvent(
                        kind: operation,
                        keyref: keyref,
                        requestingClient: clientID,
                        byteCount: byteCount,
                        summary: summary,
                        outcome: "denied",
                        detail: "user denied confirmation prompt"
                    )
                    return Self.errorJSON("operation denied by user")
                }
            }
            if requireTouchIDPerOperation, parsed.kind.requiresFreshSeedAuthorization {
                SeedStore.clearCachedSeed()
            }
            // A passphrase identity that isn't unlocked yet (e.g. after
            // auto-lock) must be unlocked before it can sign/decrypt. Prompt
            // on demand, the way Touch ID surfaces for the seed read.
            guard try await ensurePassphraseUnlocked() else {
                await logAuditEvent(
                    kind: operation,
                    keyref: keyref,
                    requestingClient: clientID,
                    byteCount: byteCount,
                    summary: summary,
                    outcome: "denied",
                    detail: "passphrase unlock cancelled"
                )
                return Self.errorJSON("passphrase unlock cancelled")
            }
            let prf = try await SeedStore.prf(salt: SeedStore.rootSalt)
            responseLine = try Self.runOp(prf: prf, userID: userIDProvider(), request: requestLine)
            if parsed.kind == .keyLookup {
                PublicCardCache.store(responseLine)
            }
            await logAuditEvent(
                kind: operation,
                keyref: keyref,
                requestingClient: clientID,
                byteCount: byteCount,
                summary: summary,
                outcome: "succeeded",
                detail: "operation completed"
            )
        } catch {
            await logAuditEvent(
                kind: operation,
                keyref: keyref,
                requestingClient: clientID,
                byteCount: byteCount,
                summary: summary,
                outcome: "failed",
                detail: error.localizedDescription
            )
            responseLine = Self.errorJSON(error.localizedDescription)
        }
        return responseLine
    }

    private func logAuditEvent(
        kind: String,
        keyref: String,
        requestingClient: String,
        byteCount: Int,
        summary: String,
        outcome: String,
        detail: String
    ) async {
        let event = OperationAuditEvent(
            id: UUID(),
            timestamp: Date(),
            kind: kind,
            keyref: keyref,
            requestingClient: requestingClient,
            byteCount: byteCount,
            summary: summary,
            details: detail,
            outcome: outcome
        )
        await OperationAuditLog.shared.append(event: event)
    }

    private static func confirm(prompt: ApprovalPrompt) async -> Bool {
        await MainActor.run { OperationApproval.present(prompt) }
    }

    /// Ensure a passphrase identity is unlocked, prompting on demand and
    /// retrying on a wrong passphrase. Returns false if the user cancels.
    /// A no-passphrase identity needs nothing and returns true immediately.
    private func ensurePassphraseUnlocked() async throws -> Bool {
        guard SeedStore.needsPassphrase() else { return true }
        var errorMessage: String?
        while SeedStore.needsPassphrase() {
            let message = errorMessage
            let entered = await MainActor.run { PassphraseUnlock.present(errorMessage: message) }
            guard let entered else {
                return false
            }
            do {
                try await SeedStore.unlock(passphrase: entered)
            } catch PasseportError.incorrectPassphrase {
                errorMessage = "That passphrase does not match this identity."
            }
        }
        return true
    }

    /// Derive the public card metadata from an already-unlocked PRF and cache
    /// it, so later `pubkeys` lookups are served without a seed unlock.
    static func refreshPublicCardCache(prf: Data, userID: String) {
        let request = #"{"op":"pubkeys","client":"Passeport app","comment":"cache public card metadata"}"#
        guard let line = try? runOp(prf: prf, userID: userID, request: request) else { return }
        PublicCardCache.store(line)
    }

    /// Shell `passeport-core op` with the PRF injected on stdin.
    private static func runOp(prf: Data, userID: String, request: String) throws -> String {
        let helperURL = try CoreLocator.helperURL()
        guard let requestObject = try JSONSerialization.jsonObject(
            with: Data(request.utf8)
        ) as? [String: Any] else {
            return errorJSON("malformed request")
        }
        let envelope: [String: Any] = [
            "prf": prf.base64URLEncodedString(),
            "user_id": userID,
            "request": requestObject
        ]
        let input = try JSONSerialization.data(withJSONObject: envelope)

        let process = Process()
        process.executableURL = helperURL
        process.arguments = ["op"]
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        stdin.fileHandleForWriting.write(input)
        try stdin.fileHandleForWriting.close()
        process.waitUntilExit()

        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0,
              let line = String(data: output, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !line.isEmpty else {
            let message = String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            )?.trimmingCharacters(in: .whitespacesAndNewlines)
            return errorJSON(message?.isEmpty == false ? message! : "key helper op failed")
        }
        return line
    }

    private static func errorJSON(_ message: String) -> String {
        let escaped = message
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "{\"ok\":false,\"error\":\"\(escaped)\"}"
    }

    // MARK: - Socket byte plumbing

    private static func readLine(fd: Int32) -> String? {
        var buffer = Data()
        var byte: UInt8 = 0
        while buffer.count < 1_000_000 {
            let n = read(fd, &byte, 1)
            if n <= 0 { break }
            if byte == UInt8(ascii: "\n") { break }
            buffer.append(byte)
        }
        return buffer.isEmpty ? nil : String(data: buffer, encoding: .utf8)
    }

    private static func writeAll(fd: Int32, string: String) {
        let bytes = Array(string.utf8)
        bytes.withUnsafeBytes { raw in
            var offset = 0
            let base = raw.bindMemory(to: UInt8.self).baseAddress!
            while offset < bytes.count {
                let written = write(fd, base + offset, bytes.count - offset)
                if written <= 0 { break }
                offset += written
            }
        }
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
