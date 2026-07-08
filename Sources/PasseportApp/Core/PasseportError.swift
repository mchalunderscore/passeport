import Foundation

enum PasseportError: LocalizedError {
    case helperMissing
    case helperFailed(String)
    case authenticationFailed
    case bridgeFailed(String)

    var errorDescription: String? {
        switch self {
        case .helperMissing:
            "The bundled key helper was not found. Build it with scripts/build-app.sh or set PASSEPORT_CORE_PATH."
        case .helperFailed(let message):
            message
        case .authenticationFailed:
            "Authentication was not completed, so the root secret stays locked."
        case .bridgeFailed(let message):
            "The GnuPG bridge could not start: \(message)"
        }
    }
}
