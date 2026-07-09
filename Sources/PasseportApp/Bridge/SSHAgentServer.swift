import Foundation

/// Native ssh-agent: answers the OpenSSH agent protocol directly from the
/// derived identity, so SSH works without GnuPG installed at all.
///
/// Only two requests are served — list identities (the auth subkey, read from
/// the public-card cache without unlocking the seed) and sign. Every
/// signature funnels through `ScdBridge.process`, i.e. the same approval
/// prompt, Touch ID policy, and audit log as the GnuPG bridge.
@SeedStoreActor
final class SSHAgentServer {
    static let shared = SSHAgentServer()

    private var listenerFD: Int32 = -1
    private var accepting = false

    private init() {}

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
            throw PasseportError.bridgeFailed("ssh agent bind() failed: \(errno)")
        }
        // Only this user may connect.
        chmod(path, 0o600)
        guard listen(fd, 8) == 0 else {
            close(fd)
            throw PasseportError.bridgeFailed("ssh agent listen() failed: \(errno)")
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

    private func acceptLoop(fd: Int32) {
        Task.detached(priority: .utility) {
            while await self.accepting {
                let client = accept(fd, nil, nil)
                if client < 0 {
                    if await self.accepting { continue }
                    break
                }
                // Drive each connection off the actor: its blocking socket
                // reads must not pin the SeedStoreActor executor (ssh holds
                // the connection open between requests), or all crypto —
                // this agent and the GnuPG bridge — would serialize behind
                // one idle read.
                Task.detached(priority: .utility) {
                    await self.serveConnection(client: client)
                }
            }
        }
    }

    private nonisolated func serveConnection(client: Int32) async {
        defer { close(client) }
        // An agent connection carries a sequence of framed requests. The
        // read/write here is nonisolated (off-actor); only `respond` hops
        // onto the actor for the actual key operation.
        while let message = Self.readMessage(fd: client) {
            let reply = await respond(to: message)
            Self.writeMessage(fd: client, payload: reply)
        }
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
        if let key = Self.authKey(fromResponseLine: PublicCardCache.load()) {
            return key
        }
        guard SeedStore.seedExists() else { return nil }
        let request = #"{"op":"pubkeys","client":"ssh (native agent)","comment":"list ssh identities"}"#
        let line = await ScdBridge.shared.process(requestLine: request)
        return Self.authKey(fromResponseLine: line)
    }

    private nonisolated static func authKey(fromResponseLine line: String?) -> Data? {
        guard let line,
              let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
              object["ok"] as? Bool == true,
              let slots = object["slots"] as? [[String: Any]],
              let auth = slots.first(where: { ($0["role"] as? String) == "auth" }),
              let qHex = auth["q"] as? String,
              let q = Hex.decode(qHex),
              q.count == 33, q.first == 0x40 else {
            return nil
        }
        return Data(q.dropFirst())
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

    private nonisolated static func writeMessage(fd: Int32, payload: Data) {
        var out = Data()
        out.appendUInt32(UInt32(payload.count))
        out.append(payload)
        out.withUnsafeBytes { raw in
            var offset = 0
            let base = raw.bindMemory(to: UInt8.self).baseAddress!
            while offset < out.count {
                let written = write(fd, base + offset, out.count - offset)
                if written <= 0 { break }
                offset += written
            }
        }
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
