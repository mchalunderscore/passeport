import CommonCrypto
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
    /// The effective key material for the PRF: the raw seed for a no-passphrase
    /// identity, or the passphrase-stretched value otherwise. Cached until lock.
    private static var cachedMaterial: Data?
    private nonisolated static let keychainPrompt = "unlock the Passeport root secret"
    private static let authenticationContext: LAContext = {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 30
        context.localizedReason = keychainPrompt
        return context
    }()

    // MARK: - Passphrase ("25th word")

    /// PBKDF2 domain-separation label for the passphrase-stretched material.
    private nonisolated static let passphraseSaltPrefix = Data("passeport-25th-word-v1".utf8)
    /// HMAC label for the public verifier that catches a wrong passphrase.
    private nonisolated static let verifierInfo = Data("passeport-passphrase-verifier-v1".utf8)
    /// OWASP-recommended floor for PBKDF2-HMAC-SHA512.
    private nonisolated static let passphraseRounds: UInt32 = 210_000
    private nonisolated static let passphraseEnabledKey = "PasseportPassphraseEnabled"
    private nonisolated static let passphraseVerifierKey = "PasseportPassphraseVerifier"

    /// True when this identity requires a passphrase to derive.
    nonisolated static func passphraseEnabled() -> Bool {
        UserDefaults.standard.bool(forKey: passphraseEnabledKey)
    }

    /// True when a passphrase is required but no session material is unlocked
    /// yet — the caller must collect it and call `unlock(passphrase:)`.
    static func needsPassphrase() -> Bool {
        passphraseEnabled() && cachedMaterial == nil
    }

    /// HMAC-SHA256 over `salt` keyed with the effective material. Stands in for
    /// the original WebAuthn PRF; see DERIVATION.md.
    static func prf(salt: Data) async throws -> Data {
        let material = try await unlockedMaterial()
        let mac = HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: material))
        return Data(mac)
    }

    /// The effective PRF material. For a no-passphrase identity this is the raw
    /// seed and unlocks transparently behind Touch ID. For a passphrase
    /// identity it must have been established via `unlock(passphrase:)`;
    /// otherwise this throws so the caller can prompt.
    private static func unlockedMaterial() async throws -> Data {
        if let cachedMaterial {
            return cachedMaterial
        }
        if passphraseEnabled() {
            throw PasseportError.passphraseRequired
        }
        let seed = try await unlockedSeed()
        cachedMaterial = seed
        return seed
    }

    /// Establish the session material for a passphrase identity: read the seed
    /// (Touch ID), stretch it with `passphrase`, and verify against the stored
    /// public commitment so a mistyped passphrase is rejected up front rather
    /// than silently deriving a different identity.
    static func unlock(passphrase: String) async throws {
        let seed = try await unlockedSeed()
        let material = deriveMaterial(seed: seed, passphrase: passphrase)
        if let expected = storedVerifier() {
            guard verifier(for: material) == expected else {
                throw PasseportError.incorrectPassphrase
            }
        }
        cachedMaterial = material
    }

    /// Turn on passphrase protection for the current identity, recording the
    /// public verifier. Used at creation/restore; a mismatched passphrase later
    /// is then caught by `unlock(passphrase:)`.
    static func enablePassphrase(_ passphrase: String) async throws {
        guard !passphrase.isEmpty else { return }
        let seed = try await unlockedSeed()
        let material = deriveMaterial(seed: seed, passphrase: passphrase)
        UserDefaults.standard.set(true, forKey: passphraseEnabledKey)
        UserDefaults.standard.set(verifier(for: material).base64EncodedString(), forKey: passphraseVerifierKey)
        cachedMaterial = material
    }

    private nonisolated static func deriveMaterial(seed: Data, passphrase: String) -> Data {
        guard !passphrase.isEmpty else { return seed }
        return pbkdf2(
            password: Data(passphrase.utf8),
            salt: passphraseSaltPrefix + seed,
            rounds: passphraseRounds,
            keyLength: expectedSeedLength
        )
    }

    private nonisolated static func verifier(for material: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: verifierInfo, using: SymmetricKey(data: material)))
    }

    private nonisolated static func storedVerifier() -> Data? {
        guard let encoded = UserDefaults.standard.string(forKey: passphraseVerifierKey) else {
            return nil
        }
        return Data(base64Encoded: encoded)
    }

    private nonisolated static func clearPassphraseState() {
        UserDefaults.standard.removeObject(forKey: passphraseEnabledKey)
        UserDefaults.standard.removeObject(forKey: passphraseVerifierKey)
    }

    private nonisolated static func pbkdf2(password: Data, salt: Data, rounds: UInt32, keyLength: Int) -> Data {
        var derived = Data(count: keyLength)
        let status = derived.withUnsafeMutableBytes { derivedRaw in
            salt.withUnsafeBytes { saltRaw in
                password.withUnsafeBytes { passwordRaw in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordRaw.bindMemory(to: Int8.self).baseAddress, password.count,
                        saltRaw.bindMemory(to: UInt8.self).baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        rounds,
                        derivedRaw.bindMemory(to: UInt8.self).baseAddress, keyLength
                    )
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed: \(status)")
        return derived
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

    /// The secure seed carries a `.userPresence` access-control and therefore
    /// lives in the data-protection keychain; every query touching it must opt
    /// in, or it silently searches the legacy keychain and finds nothing. The
    /// legacy plain-text seed (migration only) predates that and stays in the
    /// legacy keychain.
    private nonisolated static func usesDataProtection(_ service: String) -> Bool {
        service == secureService
    }

    private nonisolated static func hasSeedInKeychain(service: String) -> Bool {
        // Matching a user-presence-protected item pops the auth prompt even
        // when no data is requested; an existence check must forbid
        // interaction and treat "auth required" as "item present" instead.
        let context = LAContext()
        context.interactionNotAllowed = true
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: kCFBooleanFalse as CFBoolean,
            kSecUseAuthenticationContext: context,
        ]
        if usesDataProtection(service) {
            query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
        }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess, errSecInteractionNotAllowed:
            // Both mean the item is present: success when no auth is needed,
            // interaction-not-allowed when the presence gate would prompt.
            return true
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
            query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
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
        cachedMaterial = nil
        clearPassphraseState()
        for keychainService in [secureService, service] {
            var query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: keychainService,
                kSecAttrAccount: account,
            ]
            if usesDataProtection(keychainService) {
                query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
            }
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw keychainError(from: status)
            }
        }
    }

    static func clearCachedSeed() {
        cachedSeed = nil
        cachedMaterial = nil
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
        // A fresh identity starts with no passphrase; the caller may enable one.
        clearPassphraseState()
        cachedSeed = seed
        cachedMaterial = seed
        return seed
    }

    /// Overwrite the root seed with a recovered value (from a backup phrase).
    /// Passphrase protection is reset — the caller re-establishes it (if any)
    /// with the passphrase supplied during restore.
    static func restoreSeed(_ seed: Data) throws {
        try validateSeedLength(seed)
        try persistSeed(seed)
        clearPassphraseState()
        cachedSeed = seed
        cachedMaterial = seed
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
            kSecUseDataProtectionKeychain: kCFBooleanTrue as CFBoolean,
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
            let service = (attrs[kSecAttrService] as? String) ?? secureService
            var query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: account,
            ]
            if usesDataProtection(service) {
                query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
            }
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
