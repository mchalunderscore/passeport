import Foundation

/// Shared parsing and display model for private-key requests crossing the
/// App <-> scdaemon bridge.
struct OperationRequestMetadata {
    enum Kind: String, Codable {
        case sign
        case sshAuth
        case decrypt
        case keyLookup
        case unknown
    }

    let kind: Kind
    let keyref: String
    let requestingClient: String
    let byteCount: Int
    let hexPreview: String
    let summary: String
    let requestJSON: [String: Any]

    static let defaultClient = "gpg-agent (openpgp smartcard)"

    /// Parse one bridge request, or return `nil` if the payload is malformed.
    static func parse(requestLine: String) -> OperationRequestMetadata? {
        guard let payloadData = requestLine.data(using: .utf8),
              let decoded = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            return nil
        }

        let op = (decoded["op"] as? String)?.lowercased() ?? "unknown"
        let keyref = (decoded["keyref"] as? String) ?? "?"
        let client = (decoded["client"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let comment = (decoded["comment"] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        switch op {
        case "sign":
            let data = (decoded["data"] as? String).flatMap { Hex.decode($0) } ?? Data()
            let isAuthKey = keyref == "OPENPGP.3"
            let isSshSignature = data.starts(with: Data("SSHSIG".utf8))
            let kind: Kind = (isAuthKey || isSshSignature) ? .sshAuth : .sign
            let summary: String
            if comment.isEmpty {
                summary = "signing hash (hex prefix: \(hexPrefix(from: data)))"
            } else {
                summary = comment
            }
            return OperationRequestMetadata(
                kind: kind,
                keyref: keyref,
                requestingClient: client?.isEmpty == false ? client! : defaultClient,
                byteCount: data.count,
                hexPreview: Hex.encode(data.prefix(24)),
                summary: summary,
                requestJSON: decoded
            )

        case "ecdh":
            let point = (decoded["point"] as? String).flatMap { Hex.decode($0) } ?? Data()
            let summary = comment.isEmpty ? "decrypt request" : comment
            return OperationRequestMetadata(
                kind: .decrypt,
                keyref: keyref,
                requestingClient: client?.isEmpty == false ? client! : defaultClient,
                byteCount: point.count,
                hexPreview: Hex.encode(point.prefix(24)),
                summary: summary,
                requestJSON: decoded
            )

        case "minisignsign":
            // A seed-derived minisign signature. Classified `.sign` so it gets
            // the same unlock + approval + audit gating as any private
            // signing op (otherwise it would fall through to `.unknown` and be
            // refused). `prehash` is the 64-byte BLAKE2b digest being signed.
            let prehash = (decoded["prehash"] as? String).flatMap { Hex.decode($0) } ?? Data()
            return OperationRequestMetadata(
                kind: .sign,
                keyref: "MINISIGN.1",
                requestingClient: client?.isEmpty == false ? client! : defaultClient,
                byteCount: prehash.count,
                hexPreview: Hex.encode(prehash.prefix(24)),
                summary: comment.isEmpty ? "create a minisign signature" : comment,
                requestJSON: decoded
            )

        case "pgpdecrypt":
            let ciphertextPath = decoded["ciphertext_path"] as? String ?? ""
            let byteCount = (try? FileManager.default.attributesOfItem(atPath: ciphertextPath)[.size] as? NSNumber)?
                .intValue ?? 0
            return OperationRequestMetadata(
                kind: .decrypt,
                keyref: "OPENPGP.2",
                requestingClient: client?.isEmpty == false ? client! : defaultClient,
                byteCount: byteCount,
                hexPreview: "",
                summary: comment.isEmpty ? "decrypt an OpenPGP message" : comment,
                requestJSON: decoded
            )

        case "agedecrypt":
            let ciphertextPath = decoded["ciphertext_path"] as? String ?? ""
            let byteCount = (try? FileManager.default.attributesOfItem(atPath: ciphertextPath)[.size] as? NSNumber)?
                .intValue ?? 0
            return OperationRequestMetadata(
                kind: .decrypt,
                keyref: "OPENPGP.2",
                requestingClient: client?.isEmpty == false ? client! : defaultClient,
                byteCount: byteCount,
                hexPreview: "",
                summary: comment.isEmpty ? "decrypt an age file" : comment,
                requestJSON: decoded
            )

        case "pubkeys":
            return OperationRequestMetadata(
                kind: .keyLookup,
                keyref: keyref,
                requestingClient: client?.isEmpty == false ? client! : defaultClient,
                byteCount: 0,
                hexPreview: "",
                summary: comment.isEmpty ? "read public card metadata" : comment,
                requestJSON: decoded
            )

        default:
            return OperationRequestMetadata(
                kind: .unknown,
                keyref: keyref,
                requestingClient: client?.isEmpty == false ? client! : defaultClient,
                byteCount: 0,
                hexPreview: "",
                summary: "unknown operation",
                requestJSON: decoded
            )
        }
    }

    func toApprovalPrompt() -> ApprovalPrompt {
        let promptKind: ApprovalPrompt.Kind
        switch kind {
        case .sign: promptKind = .sign
        case .sshAuth: promptKind = .sshAuth
        case .decrypt: promptKind = .decrypt
        case .keyLookup, .unknown: promptKind = .unknown
        }
        return ApprovalPrompt(
            kind: promptKind,
            keyref: keyref,
            byteCount: byteCount,
            hexPreview: hexPreview,
            requestingClient: requestingClient,
            summary: summary
        )
    }
}

extension OperationRequestMetadata.Kind {
    var requiresFreshSeedAuthorization: Bool {
        switch self {
        case .sign, .sshAuth, .decrypt:
            return true
        case .keyLookup, .unknown:
            return false
        }
    }
}

private func hexPrefix(from data: Data) -> String {
    if data.isEmpty { return "empty payload" }
    return "\(Hex.encode(data.prefix(24)))..."
}
