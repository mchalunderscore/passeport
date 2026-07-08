import CryptoKit
import Foundation
import LocalAuthentication
import Security

@globalActor
actor SeedStoreActor {
    static let shared = SeedStoreActor()
}

/// Stores the Passeport root secret: a random 32-byte seed kept **device-local**
/// as a generic-password item in the login keychain.
///
/// The seed does not sync anywhere. Portability across machines is the user's
/// 24-word BIP39 recovery phrase (see `SeedBackup`) — a standard seed phrase
/// they control, not a cloud item. Because the item is not synchronizable and
/// lives in the file-based keychain, the app needs no keychain-access-group
/// entitlement, so it can be distributed without a provisioning profile.
///
/// User presence is enforced with a LocalAuthentication check before the seed
/// is read into the session cache.
@SeedStoreActor
enum SeedStore {
    /// Fixed PRF input for the root derivation, part of the v1 contract.
    nonisolated static let rootSalt = Data("passeport root v1".utf8)

    private nonisolated static let service = "passeport.seed"
    private nonisolated static let account = "default"
    private static var cachedSeed: Data?

    /// HMAC-SHA256 over `salt` keyed with the seed. Stands in for the original
    /// WebAuthn PRF; see DERIVATION.md.
    static func prf(salt: Data) async throws -> Data {
        let seed = try await unlockedSeed()
        let mac = HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: seed))
        return Data(mac)
    }

    nonisolated static func seedExists() -> Bool {
        guard let seed = try? copyStoredSeed() else {
            return false
        }
        return seed.count == 32
    }

    private nonisolated static func copyStoredSeed() throws -> Data {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: kCFBooleanTrue as CFBoolean,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return data
    }

    static func deleteSeed() throws {
        cachedSeed = nil
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    static func clearCachedSeed() {
        cachedSeed = nil
    }

    /// Return the raw root seed behind the Touch ID gate, for backup display.
    static func revealSeed() async throws -> Data {
        try await unlockedSeed()
    }

    /// Generate and store a fresh random seed, returning it so the caller can
    /// show the recovery phrase immediately. Throws if a seed already exists.
    @discardableResult
    static func createRandomSeed() throws -> Data {
        guard !seedExists() else {
            throw PasseportError.bridgeFailed("a seed already exists on this Mac")
        }
        let seed = makeSeed()
        try saveSeed(seed)
        cachedSeed = seed
        return seed
    }

    /// Overwrite the root seed with a recovered value (from a backup phrase).
    static func restoreSeed(_ seed: Data) throws {
        guard seed.count == 32 else {
            throw PasseportError.bridgeFailed("recovered seed must be 32 bytes")
        }
        try saveSeed(seed)
        cachedSeed = seed
    }

    private static func unlockedSeed() async throws -> Data {
        if let cachedSeed {
            return cachedSeed
        }
        if !seedExists() {
            throw PasseportError.bridgeFailed("no seed exists on this Mac")
        }
        try await requireUserPresence()
        let seed = try loadSeed()
        cachedSeed = seed
        return seed
    }

    private static func requireUserPresence() async throws {
        let context = LAContext()
        let success = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, Error>) in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "unlock the Passeport root secret"
            ) { success, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: success)
                }
            }
        }
        guard success else {
            throw PasseportError.authenticationFailed
        }
    }

    private static func makeSeed() -> Data {
        var seed = Data(count: 32)
        let status = seed.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return seed
    }

    private static func loadSeed() throws -> Data {
        let data = try copyStoredSeed()
        guard data.count == 32 else {
            throw PasseportError.bridgeFailed("stored seed is invalid")
        }
        return data
    }

    private static func saveSeed(_ seed: Data) throws {
        // Plain generic-password item in the file-based (login) keychain:
        // not synchronizable, so it never leaves the device and needs no
        // keychain-access-group entitlement.
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: seed
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: account
            ]
            let update: [CFString: Any] = [kSecValueData: seed]
            let upStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard upStatus == errSecSuccess else {
                throw NSError(domain: NSOSStatusErrorDomain, code: Int(upStatus))
            }
        } else if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
}
