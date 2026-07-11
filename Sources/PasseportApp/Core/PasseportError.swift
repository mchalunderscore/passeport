import Foundation

enum PasseportError: LocalizedError {
    case helperMissing
    case helperFailed(String)
    case authenticationFailed
    case bridgeFailed(String)
    case noIdentity
    case identityLocked
    case passphraseRequired
    case incorrectPassphrase
    case corruptPassphraseState

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
        case .noIdentity:
            "No Passeport identity is set up on this Mac. Open Passeport to create or restore one."
        case .identityLocked:
            "Passeport is locked. Open Passeport and derive or unlock your keys, then try again."
        case .passphraseRequired:
            "This vault is password protected. Enter its password in Passeport to unlock."
        case .incorrectPassphrase:
            "That password does not unlock this vault."
        case .corruptPassphraseState:
            "The identity vault is corrupt. Restore the identity from its recovery phrase."
        }
    }
}
