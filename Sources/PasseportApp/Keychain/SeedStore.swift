import CryptoKit
import Foundation
import Security
import LocalAuthentication

@globalActor
actor SeedStoreActor {
    static let shared = SeedStoreActor()
}

/// Stores the Passeport root secret: a random 32-byte seed kept **device-local**
/// as a keychain item.
///
/// The seed does not sync anywhere. Portability across machines is still via the
/// 24-word backup phrase (`SeedBackup`).
///
/// Current builds require secure, user-presence protected storage. Plain text or
/// non-secure modes are intentionally not supported.
@SeedStoreActor
enum SeedStore {
    /// Fixed PRF input for the root derivation, part of the v1 contract.
    nonisolated static let rootSalt = Data("passeport root v1".utf8)

    private nonisolated static let service = "passeport.seed"
    private nonisolated static let secureService = "passeport.seed.secure"
    private nonisolated static let account = "default"
    private nonisolated static let expectedSeedLength = 32
    private static var cachedSeed: Data?
    private nonisolated static let keychainPrompt = "unlock the Passeport root secret"
    private static let authenticationContext: LAContext = {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 30
        context.localizedReason = keychainPrompt
        return context
    }()

    /// HMAC-SHA256 over `salt` keyed with the seed. Stands in for the original
    /// WebAuthn PRF; see DERIVATION.md.
    static func prf(salt: Data) async throws -> Data {
        let seed = try await unlockedSeed()
        let mac = HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: seed))
        return Data(mac)
    }

    nonisolated static func seedExists() -> Bool {
        if hasSeedInKeychain(service: secureService) {
            return true
        }
        return hasSeedInKeychain(service: service)
    }

    nonisolated static func isSecureStorageEnabled() -> Bool {
        true
    }

    private nonisolated static func hasSeedInKeychain(service: String) -> Bool {
        // Matching a user-presence-protected item pops the auth prompt even
        // when no data is requested; an existence check must forbid
        // interaction and treat "auth required" as "item present" instead.
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: kCFBooleanFalse as CFBoolean,
            kSecUseAuthenticationContext: context,
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return true
        case errSecInteractionNotAllowed:
            return service == secureService
        case errSecItemNotFound:
            return false
        default:
            return false
        }
    }

    private nonisolated static func copyStoredSeed(service: String, authenticationContext: LAContext? = nil) throws -> Data {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: kCFBooleanTrue as CFBoolean,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        if service == secureService {
            if let authenticationContext {
                query[kSecUseAuthenticationContext] = authenticationContext
            } else {
                let context = LAContext()
                context.interactionNotAllowed = true
                query[kSecUseAuthenticationContext] = context
            }
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw keychainError(from: status)
        }
        return data
    }

    /// Read a stored seed without allowing authentication UI.
    private nonisolated static func storedSeed(for service: String) -> Data? {
        guard let seed = try? copyStoredSeed(service: service) else {
            return nil
        }
        guard seed.count == expectedSeedLength else {
            return nil
        }
        return seed
    }

    private nonisolated static func validateSeedLength(_ seed: Data) throws {
        guard seed.count == expectedSeedLength else {
            throw PasseportError.bridgeFailed("stored seed is invalid")
        }
    }

    static func deleteSeed() throws {
        cachedSeed = nil
        for keychainService in [secureService, service] {
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: keychainService,
                kSecAttrAccount: account,
            ]
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw keychainError(from: status)
            }
        }
    }

    static func clearCachedSeed() {
        cachedSeed = nil
    }

    /// Return the raw root seed behind the Touch ID gate.
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
        try persistSeed(seed)
        cachedSeed = seed
        return seed
    }

    /// Overwrite the root seed with a recovered value (from a backup phrase).
    static func restoreSeed(_ seed: Data) throws {
        try validateSeedLength(seed)
        try persistSeed(seed)
        cachedSeed = seed
    }

    /// Enforce secure-storage mode for existing credentials.
    nonisolated static func setSecureStorageEnabled(_ enabled: Bool) throws {
        guard enabled else {
            throw PasseportError.bridgeFailed("Secure Enclave-backed storage is required")
        }

        if hasSeedInKeychain(service: secureService) {
            if hasSeedInKeychain(service: service) {
                try? deleteLegacySeed()
            }
            return
        }

        guard let legacySeed = storedSeed(for: service) else {
            return
        }
        try persistSeed(legacySeed, useSecureStorage: true)
        try deleteLegacySeed()
    }

    private static func unlockedSeed() async throws -> Data {
        if let cachedSeed {
            return cachedSeed
        }
        if !seedExists() {
            throw PasseportError.bridgeFailed("no seed exists on this Mac")
        }
        let seed = try loadSeed()
        cachedSeed = seed
        return seed
    }

    private static func loadSeed() throws -> Data {
        do {
            let selected = try copyStoredSeed(service: secureService, authenticationContext: authenticationContext)
            try validateSeedLength(selected)
            return selected
        } catch let error as NSError {
            if error.domain == NSOSStatusErrorDomain, error.code == Int(errSecItemNotFound) {
                guard let legacy = storedSeed(for: service) else {
                    throw error
                }
                try migrateLegacySeedToSecureStorage(seed: legacy)
                return legacy
            }
            throw error
        }
    }

    private nonisolated static func migrateLegacySeedToSecureStorage(seed: Data) throws {
        try validateSeedLength(seed)
        try persistSeed(seed, useSecureStorage: true)
        try deleteLegacySeed()
    }

    private static func makeSeed() -> Data {
        var seed = Data(count: expectedSeedLength)
        let status = seed.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, expectedSeedLength, buffer.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return seed
    }

    private nonisolated static func persistSeed(_ seed: Data, useSecureStorage: Bool) throws {
        try validateSeedLength(seed)
        if useSecureStorage {
            try saveProtectedSeed(seed)
            return
        }
        try savePlainSeed(seed)
    }

    private nonisolated static func persistSeed(_ seed: Data) throws {
        try persistSeed(seed, useSecureStorage: true)
    }

    private nonisolated static func saveProtectedSeed(_ seed: Data) throws {
        let access = try makeSecureAccessControl()
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: secureService,
            kSecAttrAccount: account,
            kSecAttrAccessControl: access,
            kSecValueData: seed,
        ]
        try writeSeed(attrs: attrs)
    }

    private nonisolated static func savePlainSeed(_ seed: Data) throws {
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData: seed,
        ]
        try writeSeed(attrs: attrs)
    }

    private nonisolated static func writeSeed(attrs: [CFString: Any]) throws {
        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let service = attrs[kSecAttrService] ?? secureService
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: account,
            ]
            let update: [CFString: Any] = [kSecValueData: attrs[kSecValueData] as Any]
            let upStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard upStatus == errSecSuccess else {
                throw keychainError(from: upStatus)
            }
            return
        }
        if status != errSecSuccess {
            throw keychainError(from: status)
        }
    }

    private nonisolated static func deleteLegacySeed() throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw keychainError(from: status)
        }
    }

    private nonisolated static func keychainError(from status: OSStatus) -> Error {
        if status == errSecMissingEntitlement {
            return PasseportError.bridgeFailed(
                "Secure Enclave keychain access is blocked (OSStatus -34018). " +
                "This usually means the app is missing a keychain entitlement (for example, keychain sharing). " +
                "Run Passeport from a properly signed Xcode build."
            )
        }
        return NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }

    private nonisolated static func makeSecureAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = [.userPresence]
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            flags,
            &error
        ) else {
            let message =
                error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String? } ?? "unavailable"
            throw PasseportError.bridgeFailed("keychain access control failed: \(String(describing: message))")
        }
        return control
    }
}
