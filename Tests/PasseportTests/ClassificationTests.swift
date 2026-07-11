import XCTest
@testable import Passeport

/// Operation-classification is the logic behind the per-operation approval
/// prompt — including the SSH-vs-signature distinction that a real bug once
/// got wrong (a login on OPENPGP.3 was shown as a PGP signature).
final class ClassificationTests: XCTestCase {
    func testPgpSignatureOnPrimaryIsSignature() {
        let request = #"{"op":"sign","keyref":"OPENPGP.1","data":"aabbccdd"}"#
        let prompt = ApprovalPrompt.classify(request: request)
        XCTAssertEqual(prompt?.kind, .sign)
        XCTAssertEqual(prompt?.keyref, "OPENPGP.1")
    }

    func testAuthSubkeyLoginIsSSH_evenWithoutSSHSIGMagic() {
        // A real SSH login signs the userauth blob, which does NOT start with
        // "SSHSIG". Classification must key off the slot, not the payload.
        let request = #"{"op":"sign","keyref":"OPENPGP.3","data":"00000020aabbccdd"}"#
        let prompt = ApprovalPrompt.classify(request: request)
        XCTAssertEqual(prompt?.kind, .sshAuth)
    }

    func testSSHSIGBlobIsSSH() {
        // "SSHSIG" magic in hex is 535348534947.
        let request = #"{"op":"sign","keyref":"OPENPGP.1","data":"535348534947deadbeef"}"#
        let prompt = ApprovalPrompt.classify(request: request)
        XCTAssertEqual(prompt?.kind, .sshAuth)
    }

    func testEcdhIsDecrypt() {
        let request = #"{"op":"ecdh","keyref":"OPENPGP.2","point":"aabb"}"#
        XCTAssertEqual(ApprovalPrompt.classify(request: request)?.kind, .decrypt)
    }

    func testPubkeysNeedsNoPrompt() {
        XCTAssertNil(ApprovalPrompt.classify(request: #"{"op":"pubkeys"}"#))
    }

    func testMalformedRequestFallsBackToUnknown() {
        XCTAssertEqual(ApprovalPrompt.classify(request: "not json")?.kind, .unknown)
    }

    func testSignaturePreviewIsTruncatedHex() {
        let hex = String(repeating: "ab", count: 64) // 64 bytes
        let request = #"{"op":"sign","keyref":"OPENPGP.1","data":"\#(hex)"}"#
        let prompt = ApprovalPrompt.classify(request: request)
        XCTAssertEqual(prompt?.byteCount, 64)
        // Preview caps at 24 bytes = 48 hex chars.
        XCTAssertEqual(prompt?.hexPreview.count, 48)
    }

    func testMinisignIsClassifiedAsApprovalGatedSignature() {
        let digest = String(repeating: "ab", count: 64)
        let metadata = OperationRequestMetadata.parse(
            requestLine: #"{"op":"minisignsign","prehash":"\#(digest)","client":"  minisign  "}"#
        )
        XCTAssertEqual(metadata?.kind, .sign)
        XCTAssertEqual(metadata?.keyref, "MINISIGN.1")
        XCTAssertEqual(metadata?.byteCount, 64)
        XCTAssertEqual(metadata?.requestingClient, "minisign")
    }

    func testBlankClientUsesSafeDefaultAndCommentOverridesSummary() {
        let metadata = OperationRequestMetadata.parse(
            requestLine: #"{"op":"sign","keyref":"OPENPGP.1","data":"00","client":"  ","comment":" release tag "}"#
        )
        XCTAssertEqual(metadata?.requestingClient, OperationRequestMetadata.defaultClient)
        XCTAssertEqual(metadata?.summary, "release tag")
    }

    func testOnlyPrivateOperationsRequireFreshAuthorization() {
        XCTAssertTrue(OperationRequestMetadata.Kind.sign.requiresFreshSeedAuthorization)
        XCTAssertTrue(OperationRequestMetadata.Kind.sshAuth.requiresFreshSeedAuthorization)
        XCTAssertTrue(OperationRequestMetadata.Kind.decrypt.requiresFreshSeedAuthorization)
        XCTAssertFalse(OperationRequestMetadata.Kind.keyLookup.requiresFreshSeedAuthorization)
        XCTAssertFalse(OperationRequestMetadata.Kind.unknown.requiresFreshSeedAuthorization)
    }
}

final class SSHWireFormatTests: XCTestCase {
    func testUInt32AndStringRoundTrip() {
        var encoded = Data()
        encoded.appendUInt32(0x0102_03ff)
        encoded.appendString(Data("hello".utf8))
        var reader = SSHWireReader(data: encoded)
        XCTAssertEqual(reader.readUInt32(), 0x0102_03ff)
        XCTAssertEqual(reader.readString(), Data("hello".utf8))
    }

    func testTruncatedLengthAndPayloadAreRejected() {
        var shortLength = SSHWireReader(data: Data([0, 0, 0]))
        XCTAssertNil(shortLength.readUInt32())

        var truncated = Data()
        truncated.appendUInt32(8)
        truncated.append(Data([1, 2]))
        var reader = SSHWireReader(data: truncated)
        XCTAssertNil(reader.readString())
    }

    func testZeroLengthStringIsAccepted() {
        var encoded = Data()
        encoded.appendUInt32(0)
        var reader = SSHWireReader(data: encoded)
        XCTAssertEqual(reader.readString(), Data())
    }
}

final class OperationAuditLogTests: XCTestCase {
    func testAtomicPersistenceAndObservableFailure() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("passeport-audit-tests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let logURL = directory.appendingPathComponent("audit.json")
        let event = OperationAuditEvent(
            id: UUID(),
            timestamp: Date(),
            kind: "sign",
            keyref: "OPENPGP.1",
            requestingClient: "test",
            byteCount: 32,
            summary: "test",
            details: "test",
            outcome: "succeeded"
        )
        let log = OperationAuditLog(storageURL: logURL)
        await log.append(event: event)
        let initialWarning = await log.persistenceWarning()
        XCTAssertNil(initialWarning)
        XCTAssertEqual(try JSONDecoder().decode([OperationAuditEvent].self, from: Data(contentsOf: logURL)).count, 1)

        let blocker = directory.appendingPathComponent("not-a-directory")
        try Data().write(to: blocker)
        let failingLog = OperationAuditLog(storageURL: blocker.appendingPathComponent("audit.json"))
        await failingLog.append(event: event)
        let failureWarning = await failingLog.persistenceWarning()
        XCTAssertNotNil(failureWarning)
    }

    func testNewestFirstLimitAndClear() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("passeport-audit-order-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let logURL = directory.appendingPathComponent("audit.json")
        let log = OperationAuditLog(storageURL: logURL)
        for index in 0..<3 {
            await log.append(event: event(index))
        }
        let limited = await log.events(limit: 2)
        XCTAssertEqual(limited.map(\.summary), ["event 2", "event 1"])
        await log.clear()
        let empty = await log.events()
        XCTAssertTrue(empty.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: logURL.path))
    }

    func testCorruptLogIsQuarantined() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("passeport-audit-corrupt-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let logURL = directory.appendingPathComponent("audit.json")
        try Data("not-json".utf8).write(to: logURL)
        let log = OperationAuditLog(storageURL: logURL)
        let events = await log.events()
        XCTAssertTrue(events.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: logURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: logURL.appendingPathExtension("corrupt").path))
    }

    private func event(_ index: Int) -> OperationAuditEvent {
        OperationAuditEvent(
            id: UUID(), timestamp: Date(timeIntervalSince1970: TimeInterval(index)),
            kind: "sign", keyref: "OPENPGP.1", requestingClient: "test",
            byteCount: index, summary: "event \(index)", details: "", outcome: "succeeded"
        )
    }
}

final class RecoveryHardeningTests: XCTestCase {
    func testBackupReminderDuePolicy() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        XCTAssertFalse(AppModel.backupVerificationIsDue(verifiedAt: now.addingTimeInterval(-89 * 86_400), reminderDays: 90, now: now))
        XCTAssertTrue(AppModel.backupVerificationIsDue(verifiedAt: now.addingTimeInterval(-90 * 86_400), reminderDays: 90, now: now))
        XCTAssertTrue(AppModel.backupVerificationIsDue(verifiedAt: nil, reminderDays: 90, now: now))
        XCTAssertFalse(AppModel.backupVerificationIsDue(verifiedAt: nil, reminderDays: 0, now: now))
    }

    func testRestoreSuccessDoesNotRollback() throws {
        var applied = false
        var rolledBack = false
        try RestoreTransaction.commit {
            applied = true
        } rollback: {
            rolledBack = true
        }
        XCTAssertTrue(applied)
        XCTAssertFalse(rolledBack)
    }

    func testBackupDrillValidationNormalizesAnswersAndReportsPosition() async {
        let session = BackupDrillSession(wordIndices: [2, 9], expectedWords: ["apple", "zebra"])
        let valid = await AppModel.validateBackupDrill(answers: [" APPLE ", "Zebra\n"], session: session)
        let incorrect = await AppModel.validateBackupDrill(answers: ["apple", "wrong"], session: session)
        let short = await AppModel.validateBackupDrill(answers: ["apple"], session: session)
        XCTAssertNil(valid)
        XCTAssertEqual(
            incorrect,
            .incorrectWord(position: 9)
        )
        XCTAssertEqual(
            short,
            .wrongAnswerCount
        )
    }

    func testRestoreFailureAlwaysRollsBackAndPreservesCommitError() {
        var rolledBack = false
        XCTAssertThrowsError(try RestoreTransaction.commit {
            throw TestFailure.commit
        } rollback: {
            rolledBack = true
        }) { error in
            XCTAssertEqual(error as? TestFailure, .commit)
        }
        XCTAssertTrue(rolledBack)
    }

    func testRestoreReportsCommitAndRollbackFailure() {
        XCTAssertThrowsError(try RestoreTransaction.commit {
            throw TestFailure.commit
        } rollback: {
            throw TestFailure.rollback
        }) { error in
            XCTAssertTrue(error.localizedDescription.contains("commit failed"))
            XCTAssertTrue(error.localizedDescription.contains("rollback failed"))
        }
    }

    private enum TestFailure: LocalizedError, Equatable {
        case commit
        case rollback

        var errorDescription: String? {
            switch self {
            case .commit: "commit failed"
            case .rollback: "rollback failed"
            }
        }
    }
}

final class SemanticVersionTests: XCTestCase {
    func testParsesPlainAndVPrefixedVersions() {
        XCTAssertEqual(SemanticVersion("0.1.0"), SemanticVersion("v0.1.0"))
        XCTAssertEqual(SemanticVersion("V2.4.6"), SemanticVersion("2.4.6"))
    }

    func testOrdersEachComponentNumerically() {
        XCTAssertLessThan(SemanticVersion("0.1.9")!, SemanticVersion("0.2.0")!)
        XCTAssertLessThan(SemanticVersion("0.9.9")!, SemanticVersion("1.0.0")!)
        XCTAssertLessThan(SemanticVersion("1.0.9")!, SemanticVersion("1.0.10")!)
    }

    func testRejectsNonSemverTags() {
        XCTAssertNil(SemanticVersion("release-1"))
        XCTAssertNil(SemanticVersion("1.2"))
        XCTAssertNil(SemanticVersion("1.2.x"))
    }

    func testIgnoresSemverBuildAndPrereleaseSuffixes() {
        XCTAssertEqual(SemanticVersion("1.2.3-beta.1"), SemanticVersion("1.2.3"))
        XCTAssertEqual(SemanticVersion("1.2.3+build.9"), SemanticVersion("1.2.3"))
    }

    func testRejectsNegativeEmptyAndExtraComponents() {
        XCTAssertNil(SemanticVersion("-1.2.3"))
        XCTAssertNil(SemanticVersion("1..3"))
        XCTAssertNil(SemanticVersion("1.2.3.4"))
    }
}

final class PublicCardCacheParsingTests: XCTestCase {
    private let point = "40" + String(repeating: "ab", count: 32)

    func testExtractsNamedRoleAndStripsPointPrefix() {
        let line = #"{"ok":true,"slots":[{"role":"sign","q":"\#(point)"}]}"#
        XCTAssertEqual(PublicCardCache.publicKey(role: "sign", inResponseLine: line), Data(repeating: 0xab, count: 32))
    }

    func testRejectsErrorsMissingRolesAndMalformedPoints() {
        XCTAssertNil(PublicCardCache.publicKey(role: "sign", inResponseLine: nil))
        XCTAssertNil(PublicCardCache.publicKey(role: "sign", inResponseLine: #"{"ok":false,"slots":[]}"#))
        XCTAssertNil(PublicCardCache.publicKey(role: "sign", inResponseLine: #"{"ok":true,"slots":[]}"#))
        XCTAssertNil(PublicCardCache.publicKey(role: "sign", inResponseLine: #"{"ok":true,"slots":[{"role":"sign","q":"41aa"}]}"#))
    }
}

final class StringPolicyTests: XCTestCase {
    func testTrimmedNonEmptyUsesFallbackOnlyForWhitespace() {
        XCTAssertEqual("  value  ".trimmedNonEmpty(defaultValue: "fallback"), "value")
        XCTAssertEqual(" \n\t ".trimmedNonEmpty(defaultValue: "fallback"), "fallback")
    }
}

final class RustHelperInteropTests: XCTestCase {
    func testRecoveryPhraseRoundTripsAcrossSwiftAndRust() throws {
        let seed = Data(0..<32)
        let phrase = try SeedBackup.recoveryPhrase(seed: seed)
        XCTAssertEqual(phrase.split(separator: " ").count, 24)
        XCTAssertEqual(try SeedBackup.seed(fromPhrase: phrase), seed)
    }

    func testRecoveryRejectsInvalidMnemonic() {
        XCTAssertThrowsError(try SeedBackup.seed(fromPhrase: String(repeating: "invalid ", count: 24)))
    }

    func testFrozenRustDerivationSelfTestPasses() {
        switch DeterminismCheck.run() {
        case .passed:
            break
        case .failed(let message):
            XCTFail(message)
        }
    }
}

final class SeedDerivationPolicyTests: XCTestCase {
    func testPreviewPRFIsDeterministicAndAlways32Bytes() async throws {
        let seed = Data(0..<32)
        let salt = Data("test salt".utf8)
        let first = try await SeedStore.previewPRF(seed: seed, passphrase: "correct horse", salt: salt)
        let second = try await SeedStore.previewPRF(seed: seed, passphrase: "correct horse", salt: salt)
        XCTAssertEqual(first, second)
        XCTAssertEqual(first.count, 32)
    }

    func testPasswordDoesNotChangeIdentityAndSaltStillDomainSeparatesPRF() async throws {
        let seed = Data(repeating: 7, count: 32)
        let base = try await SeedStore.previewPRF(seed: seed, passphrase: "x", salt: Data("a".utf8))
        let passphrase = try await SeedStore.previewPRF(seed: seed, passphrase: "y", salt: Data("a".utf8))
        let salt = try await SeedStore.previewPRF(seed: seed, passphrase: "x", salt: Data("b".utf8))
        XCTAssertEqual(base, passphrase)
        XCTAssertNotEqual(base, salt)
        XCTAssertNotEqual(passphrase, salt)
    }

    func testEmptyPasswordIsAccepted() async throws {
        let seed = Data(repeating: 7, count: 32)
        let withoutPassword = try await SeedStore.previewPRF(seed: seed, passphrase: "", salt: Data("a".utf8))
        let withPassword = try await SeedStore.previewPRF(seed: seed, passphrase: "secret", salt: Data("a".utf8))
        XCTAssertEqual(withoutPassword, withPassword)
    }

    func testVaultRoundTripsAndRejectsWrongPassphrase() throws {
        let seed = Data(0..<32)
        XCTAssertEqual(
            try SeedStore.vaultRoundTripForTesting(seed: seed, passphrase: "a long local secret"),
            seed
        )
        XCTAssertTrue(
            SeedStore.vaultRejectsWrongPassphraseForTesting(seed: seed, passphrase: "a long local secret")
        )
        XCTAssertEqual(try SeedStore.unprotectedVaultRoundTripForTesting(seed: seed), seed)
    }
}

private func XCTAssertThrowsErrorAsync(
    _ expression: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        // Expected.
    }
}
