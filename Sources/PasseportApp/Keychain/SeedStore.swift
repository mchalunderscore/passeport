import CommonCrypto
import CryptoKit
import Foundation
import Security

extension Notification.Name {
    /// Posted after the in-process vault cache becomes usable. This lets UI
    /// state catch up when a bridge operation, rather than the main window,
    /// supplied the vault password.
    static let passeportSeedDidUnlock = Notification.Name("PasseportSeedDidUnlock")
}

@globalActor
actor SeedStoreActor {
    static let shared = SeedStoreActor()
}

enum RestoreTransaction {
    static func commit(apply: () throws -> Void, rollback: () throws -> Void) throws {
        do {
            try apply()
        } catch let commitError {
            do { try rollback() }
            catch let rollbackError {
                throw PasseportError.bridgeFailed(
                    "identity restore failed (\(commitError.localizedDescription)) and rollback also failed: \(rollbackError.localizedDescription)"
                )
            }
            throw commitError
        }
    }
}

/// Stores the 32-byte root seed in an authenticated encrypted file. The vault
/// is intentionally independent of the app's code signature, so ad-hoc and
/// unsigned builds can retain the same identity across upgrades.
@SeedStoreActor
enum SeedStore {
    nonisolated static let rootSalt = Data("passeport root v1".utf8)

    private nonisolated static let expectedSeedLength = 32
    private nonisolated static let vaultRounds: UInt32 = 600_000
    private nonisolated static let vaultAAD = Data("passeport-seed-vault-v1".utf8)
    private struct Vault: Codable, Equatable {
        let version: Int
        let passwordProtected: Bool
        let kdf: String?
        let rounds: UInt32?
        let salt: Data?
        let sealedSeed: Data?
        let seed: Data?
    }

    private static var cachedSeed: Data?
    private static var cachedMaterial: Data?

    private nonisolated static var vaultURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Passeport", isDirectory: true)
            .appendingPathComponent("identity.vault")
    }

    nonisolated static func seedExists() -> Bool {
        FileManager.default.fileExists(atPath: vaultURL.path)
    }

    nonisolated static func passphraseEnabled() -> Bool {
        guard let data = try? Data(contentsOf: vaultURL),
              let vault = try? JSONDecoder().decode(Vault.self, from: data) else { return false }
        return vault.passwordProtected
    }

    static func needsPassphrase() -> Bool {
        seedExists() && passphraseEnabled() && cachedMaterial == nil
    }

    static func canDeriveSilently() -> Bool { cachedMaterial != nil }

    static func prf(salt: Data) async throws -> Data {
        guard let cachedMaterial else { throw PasseportError.passphraseRequired }
        return Data(HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: cachedMaterial)))
    }

    static func unlock(passphrase: String) async throws {
        guard FileManager.default.fileExists(atPath: vaultURL.path) else { throw PasseportError.noIdentity }
        let vault = try loadVault()
        let seed = try decrypt(vault: vault, passphrase: passphrase)
        cache(seed: seed)
    }

    /// Persist the freshly generated seed, encrypting it when a password was supplied.
    static func enablePassphrase(_ passphrase: String) async throws {
        guard let seed = cachedSeed else { throw PasseportError.noIdentity }
        try persistVault(seed: seed, passphrase: passphrase)
        cache(seed: seed)
    }

    static func previewPRF(passphrase: String, salt: Data) async throws -> Data {
        guard let seed = cachedSeed else { throw PasseportError.passphraseRequired }
        return Data(HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: seed)))
    }

    static func previewPRF(seed: Data, passphrase: String, salt: Data) throws -> Data {
        try validateSeedLength(seed)
        return Data(HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: seed)))
    }

    static func commitRestoredIdentity(seed: Data, passphrase: String) async throws {
        try validateSeedLength(seed)
        let previous = try? Data(contentsOf: vaultURL)
        try RestoreTransaction.commit {
            try persistVault(seed: seed, passphrase: passphrase)
            cache(seed: seed)
        } rollback: {
            if let previous {
                try previous.write(to: vaultURL, options: .atomic)
            } else {
                try? FileManager.default.removeItem(at: vaultURL)
            }
        }
    }

    static func createRandomSeed() throws -> Data {
        guard !seedExists() else { throw PasseportError.bridgeFailed("a seed already exists on this Mac") }
        let seed = makeSeed()
        cachedSeed = seed
        cachedMaterial = nil
        return seed
    }

    static func restoreSeed(_ seed: Data) throws {
        try validateSeedLength(seed)
        cachedSeed = seed
        cachedMaterial = nil
    }

    static func revealSeed() async throws -> Data {
        guard let cachedSeed else { throw PasseportError.passphraseRequired }
        return cachedSeed
    }

    static func deleteSeed() throws {
        clearCachedSeed()
        if FileManager.default.fileExists(atPath: vaultURL.path) {
            try FileManager.default.removeItem(at: vaultURL)
        }
    }

    static func clearCachedSeed() {
        cachedSeed = nil
        cachedMaterial = nil
    }

    /// Unlock approval is the user-presence boundary in unsigned mode. Per-op
    /// confirmation remains available, but there is no signature-bound Secure
    /// Enclave credential to re-authenticate against.
    static func requireFreshAuthorization() async throws {
        guard cachedMaterial != nil else { throw PasseportError.passphraseRequired }
    }

    // MARK: - Vault format

    private nonisolated static func makeVault(
        seed: Data,
        passphrase: String,
        salt: Data? = nil
    ) throws -> Vault {
        try validateSeedLength(seed)
        if passphrase.isEmpty {
            return Vault(
                version: 1,
                passwordProtected: false,
                kdf: nil,
                rounds: nil,
                salt: nil,
                sealedSeed: nil,
                seed: seed
            )
        }
        let salt = salt ?? randomData(count: 32)
        let keyData = pbkdf2(password: Data(passphrase.utf8), salt: salt, rounds: vaultRounds, keyLength: 32)
        let box = try ChaChaPoly.seal(seed, using: SymmetricKey(data: keyData), authenticating: vaultAAD)
        return Vault(
            version: 1,
            passwordProtected: true,
            kdf: "pbkdf2-hmac-sha512",
            rounds: vaultRounds,
            salt: salt,
            sealedSeed: box.combined,
            seed: nil
        )
    }

    private nonisolated static func decrypt(vault: Vault, passphrase: String) throws -> Data {
        guard vault.version == 1 else {
            throw PasseportError.corruptPassphraseState
        }
        if !vault.passwordProtected {
            guard let seed = vault.seed else { throw PasseportError.corruptPassphraseState }
            try validateSeedLength(seed)
            return seed
        }
        guard !passphrase.isEmpty else { throw PasseportError.passphraseRequired }
        guard vault.kdf == "pbkdf2-hmac-sha512",
              let rounds = vault.rounds, rounds >= 210_000,
              let salt = vault.salt, salt.count >= 16,
              let sealedSeed = vault.sealedSeed else {
            throw PasseportError.corruptPassphraseState
        }
        let keyData = pbkdf2(password: Data(passphrase.utf8), salt: salt, rounds: rounds, keyLength: 32)
        do {
            let box = try ChaChaPoly.SealedBox(combined: sealedSeed)
            let seed = try ChaChaPoly.open(box, using: SymmetricKey(data: keyData), authenticating: vaultAAD)
            try validateSeedLength(seed)
            return seed
        } catch {
            throw PasseportError.incorrectPassphrase
        }
    }

    private nonisolated static func persistVault(
        seed: Data,
        passphrase: String
    ) throws {
        let vault = try makeVault(seed: seed, passphrase: passphrase)
        let directory = vaultURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let data = try JSONEncoder().encode(vault)
        try data.write(to: vaultURL, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: vaultURL.path)
    }

    private nonisolated static func loadVault() throws -> Vault {
        do {
            return try JSONDecoder().decode(Vault.self, from: Data(contentsOf: vaultURL))
        } catch {
            throw PasseportError.corruptPassphraseState
        }
    }

    private static func cache(seed: Data) {
        cachedSeed = seed
        cachedMaterial = seed
        NotificationCenter.default.post(name: .passeportSeedDidUnlock, object: nil)
    }

    // MARK: - Testable crypto helpers

    nonisolated static func vaultRoundTripForTesting(
        seed: Data,
        passphrase: String
    ) throws -> Data {
        try decrypt(
            vault: makeVault(seed: seed, passphrase: passphrase),
            passphrase: passphrase
        )
    }

    nonisolated static func vaultRejectsWrongPassphraseForTesting(seed: Data, passphrase: String) -> Bool {
        guard let vault = try? makeVault(seed: seed, passphrase: passphrase) else { return true }
        return (try? decrypt(vault: vault, passphrase: passphrase + "!")) == nil
    }

    nonisolated static func unprotectedVaultRoundTripForTesting(seed: Data) throws -> Data {
        try decrypt(vault: makeVault(seed: seed, passphrase: ""), passphrase: "")
    }

    private nonisolated static func validateSeedLength(_ seed: Data) throws {
        guard seed.count == expectedSeedLength else { throw PasseportError.bridgeFailed("stored seed is invalid") }
    }

    private nonisolated static func makeSeed() -> Data { randomData(count: expectedSeedLength) }

    private nonisolated static func randomData(count: Int) -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return data
    }

    private nonisolated static func pbkdf2(
        password: Data,
        salt: Data,
        rounds: UInt32,
        keyLength: Int
    ) -> Data {
        var derived = Data(count: keyLength)
        let status = derived.withUnsafeMutableBytes { derivedRaw in
            salt.withUnsafeBytes { saltRaw in
                password.withUnsafeBytes { passwordRaw in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordRaw.bindMemory(to: Int8.self).baseAddress, password.count,
                        saltRaw.bindMemory(to: UInt8.self).baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), rounds,
                        derivedRaw.bindMemory(to: UInt8.self).baseAddress, keyLength
                    )
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed: \(status)")
        return derived
    }
}
