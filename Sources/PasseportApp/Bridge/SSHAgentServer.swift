import Foundation

/// Native ssh-agent: answers the OpenSSH agent protocol directly from the
/// derived identity, so SSH works without GnuPG installed at all.
///
/// Only two requests are served — list identities (the auth subkey, read from
/// the public-card cache without unlocking the seed) and sign. Every
/// signature funnels through `ScdBridge.process`, i.e. the same approval
/// prompt, vault-unlock policy, and audit log as the GnuPG bridge.
@SeedStoreActor
final class SSHAgentServer {
    static let shared = SSHAgentServer()

    private var listenerFD: Int32 = -1
    /// Read by the dedicated accept/connection threads to observe shutdown
    /// without hopping onto the actor; guarded by `stateLock`.
    private nonisolated(unsafe) var accepting = false
    private let stateLock = NSLock()

    private init() {}

    private nonisolated var isAccepting: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return accepting
    }

    private nonisolated func setAccepting(_ value: Bool) {
        stateLock.lock()
        defer { stateLock.unlock() }
        accepting = value
    }

    nonisolated static var socketURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport", isDirectory: true)
            .appendingPathComponent("ssh-agent.sock")
    }

    var isRunning: Bool { listenerFD >= 0 }

    /// Message type bytes from the OpenSSH agent protocol.
    private enum MessageType {
        static let failure: UInt8 = 5
        static let requestIdentities: UInt8 = 11
        static let identitiesAnswer: UInt8 = 12
        static let signRequest: UInt8 = 13
        static let signResponse: UInt8 = 14
    }

    func start() throws {
        guard listenerFD < 0 else { return }

        let url = Self.socketURL
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let path = url.path
        // Unix socket paths are limited to 104 bytes on Darwin.
        guard path.utf8.count < 104 else {
            throw PasseportError.bridgeFailed("ssh agent socket path too long: \(path)")
        }
        unlink(path)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw PasseportError.bridgeFailed("socket() failed: \(errno)")
        }
        Self.setNoSigpipe(fd)

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
                    "the ssh agent socket is already in use — another Passeport instance may already be serving it"
                )
            }
            throw PasseportError.bridgeFailed("ssh agent bind() failed: \(errno)")
        }
        // Only this user may connect.
        chmod(path, 0o600)
        guard listen(fd, 8) == 0 else {
            close(fd)
            throw PasseportError.bridgeFailed("ssh agent listen() failed: \(errno)")
        }

        listenerFD = fd
        setAccepting(true)
        acceptLoop(fd: fd)
    }

    func stop() {
        setAccepting(false)
        if listenerFD >= 0 {
            close(listenerFD)
            listenerFD = -1
        }
        unlink(Self.socketURL.path)
    }

    /// Runs on a dedicated thread: `accept(2)` blocks indefinitely between
    /// connections, and ssh clients (ControlMaster, agent forwarding) hold
    /// connections open for minutes. Blocking syscalls must stay off the
    /// Swift cooperative pool — each pinned pool thread is one of only
    /// ~one-per-core, so a handful of idle connections would starve every
    /// task in the app.
    private nonisolated func acceptLoop(fd: Int32) {
        let acceptThread = Thread { [self] in
            while isAccepting {
                let client = accept(fd, nil, nil)
                if client < 0 {
                    if isAccepting { continue }
                    break
                }
                // A peer that hangs up mid-reply must surface as EPIPE from
                // write(2), never as a process-killing SIGPIPE.
                Self.setNoSigpipe(client)
                // One dedicated thread per connection: its reads block
                // between requests, and blocking must not pin the actor or
                // the cooperative pool, or all crypto — this agent and the
                // GnuPG bridge — would serialize behind one idle read.
                let connectionThread = Thread { [self] in
                    serveConnection(client: client)
                }
                connectionThread.name = "SSHAgentServer.connection"
                connectionThread.start()
            }
        }
        acceptThread.name = "SSHAgentServer.accept"
        acceptThread.start()
    }

    /// Runs on the connection's dedicated thread. An agent connection
    /// carries a sequence of framed requests; the blocking read/write stays
    /// on this thread, and only `respond` bridges into Swift concurrency for
    /// the actual key operation.
    private nonisolated func serveConnection(client: Int32) {
        defer { close(client) }
        while let message = Self.readMessage(fd: client) {
            let reply = respondFromThread(to: message)
            // A short write means the peer hung up (EPIPE) — a normal
            // disconnect, so just end the connection.
            guard Self.writeMessage(fd: client, payload: reply) else { return }
        }
    }

    /// Bridges the connection thread into Swift concurrency and waits for
    /// the reply. Parking this thread on a semaphore is acceptable because
    /// it is a dedicated thread, not a cooperative-pool thread; the actual
    /// work — approval prompt, vault unlock, signing — runs inside the
    /// task on the actor.
    private nonisolated func respondFromThread(to message: Data) -> Data {
        let box = ReplyBox()
        let semaphore = DispatchSemaphore(value: 0)
        Task {
            box.reply = await self.respond(to: message)
            semaphore.signal()
        }
        semaphore.wait()
        return box.reply
    }

    /// Carries the reply across the semaphore bridge; the signal/wait pair
    /// orders the task's write before the thread's read.
    private final class ReplyBox: @unchecked Sendable {
        var reply = Data([MessageType.failure])
    }

    private func respond(to message: Data) async -> Data {
        switch message.first {
        case MessageType.requestIdentities:
            return await identitiesAnswer()
        case MessageType.signRequest:
            return await signResponse(body: message.dropFirst())
        default:
            return Data([MessageType.failure])
        }
    }

    /// The one identity this agent serves: the auth subkey. An empty answer
    /// (not a failure) when no seed exists yet, matching agents with no keys.
    private func identitiesAnswer() async -> Data {
        var out = Data([MessageType.identitiesAnswer])
        guard let key = await authPublicKey() else {
            out.appendUInt32(0)
            return out
        }
        out.appendUInt32(1)
        out.appendString(Self.keyBlob(publicKey: key))
        out.appendString(Data("passeport".utf8))
        return out
    }

    private func signResponse(body: Data) async -> Data {
        var reader = SSHWireReader(data: body)
        guard let requestedKey = reader.readString(),
              let payload = reader.readString(),
              reader.readUInt32() != nil else {
            return Data([MessageType.failure])
        }
        // Only sign for the key we advertised.
        guard let key = await authPublicKey(),
              Self.keyBlob(publicKey: key) == requestedKey else {
            return Data([MessageType.failure])
        }

        let request: [String: Any] = [
            "op": "sign",
            "keyref": "OPENPGP.3",
            "data": Hex.encode(payload),
            "client": "ssh (native agent)",
            "comment": "ssh authentication",
        ]
        guard let requestData = try? JSONSerialization.data(withJSONObject: request),
              let requestLine = String(data: requestData, encoding: .utf8) else {
            return Data([MessageType.failure])
        }
        let responseLine = await ScdBridge.shared.process(requestLine: requestLine)
        guard let object = try? JSONSerialization.jsonObject(with: Data(responseLine.utf8)) as? [String: Any],
              object["ok"] as? Bool == true,
              let sigHex = object["sig"] as? String,
              let signature = Hex.decode(sigHex),
              signature.count == 64 else {
            return Data([MessageType.failure])
        }

        var signatureBlob = Data()
        signatureBlob.appendString(Data("ssh-ed25519".utf8))
        signatureBlob.appendString(signature)
        var out = Data([MessageType.signResponse])
        out.appendString(signatureBlob)
        return out
    }

    /// The raw 32-byte Ed25519 auth public key, from the public-card cache
    /// when possible; falls back to one live lookup (which fills the cache).
    private func authPublicKey() async -> Data? {
        if let key = PublicCardCache.publicKey(role: "auth", inResponseLine: PublicCardCache.load()) {
            return key
        }
        guard SeedStore.seedExists() else { return nil }
        let request = #"{"op":"pubkeys","client":"ssh (native agent)","comment":"list ssh identities"}"#
        let line = await ScdBridge.shared.process(requestLine: request)
        return PublicCardCache.publicKey(role: "auth", inResponseLine: line)
    }

    /// OpenSSH public key wire blob: string "ssh-ed25519" + string key.
    nonisolated static func keyBlob(publicKey: Data) -> Data {
        var blob = Data()
        blob.appendString(Data("ssh-ed25519".utf8))
        blob.appendString(publicKey)
        return blob
    }

    // MARK: - Framing

    private nonisolated static func readMessage(fd: Int32) -> Data? {
        guard let header = readExactly(fd: fd, count: 4) else { return nil }
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= 262_144 else { return nil }
        return readExactly(fd: fd, count: Int(length))
    }

    private nonisolated static func readExactly(fd: Int32, count: Int) -> Data? {
        var buffer = Data()
        buffer.reserveCapacity(count)
        var chunk = [UInt8](repeating: 0, count: min(count, 65536))
        while buffer.count < count {
            let n = read(fd, &chunk, min(chunk.count, count - buffer.count))
            if n <= 0 { return nil }
            buffer.append(contentsOf: chunk[0..<n])
        }
        return buffer
    }

    /// Returns `false` when the write cannot complete — with SO_NOSIGPIPE
    /// set, a hung-up peer yields a plain EPIPE error here rather than a
    /// signal, and the caller treats it as a normal disconnect.
    private nonisolated static func writeMessage(fd: Int32, payload: Data) -> Bool {
        var out = Data()
        out.appendUInt32(UInt32(payload.count))
        out.append(payload)
        return out.withUnsafeBytes { raw in
            var offset = 0
            let base = raw.bindMemory(to: UInt8.self).baseAddress!
            while offset < out.count {
                let written = write(fd, base + offset, out.count - offset)
                if written <= 0 { return false }
                offset += written
            }
            return true
        }
    }

    /// Suppress SIGPIPE on this socket so writes to a hung-up peer fail
    /// with EPIPE instead of killing the process.
    private nonisolated static func setNoSigpipe(_ fd: Int32) {
        var on: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    }
}

/// Cursor over ssh wire-format fields (uint32-length-prefixed strings).
struct SSHWireReader {
    private let data: Data
    private var offset = 0

    init(data: Data) {
        // Rebase so indices start at zero regardless of the source slice.
        self.data = Data(data)
    }

    mutating func readUInt32() -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        let value = data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4
        return value
    }

    mutating func readString() -> Data? {
        guard let length = readUInt32(),
              offset + Int(length) <= data.count else {
            return nil
        }
        let value = data.subdata(in: offset..<offset + Int(length))
        offset += Int(length)
        return value
    }
}

extension Data {
    mutating func appendUInt32(_ value: UInt32) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }

    /// Append an ssh wire-format string (uint32 length + bytes).
    mutating func appendString(_ payload: Data) {
        appendUInt32(UInt32(payload.count))
        append(payload)
    }
}
