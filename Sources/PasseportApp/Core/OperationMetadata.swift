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
