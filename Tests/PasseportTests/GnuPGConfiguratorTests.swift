import XCTest
@testable import Passeport

final class GnuPGConfiguratorTests: XCTestCase {
    func testCorruptManagedSnapshotsAreRejected() {
        let corrupt = Data("{not-json".utf8)
        XCTAssertFalse(GitConfigurator.managedStateDataIsValid(corrupt))
        XCTAssertFalse(GnuPGConfigurator.managedStateDataIsValid(corrupt))

        let gitValid = Data(#"{"settings":[]}"#.utf8)
        XCTAssertTrue(GitConfigurator.managedStateDataIsValid(gitValid))
        let gnupgValid = Data(#"{"addedSSHSupport":true,"managedScdaemonLine":"scdaemon-program /tmp/passeport-scd"}"#.utf8)
        XCTAssertTrue(GnuPGConfigurator.managedStateDataIsValid(gnupgValid))
    }
    func testGitRemovalSafetyRejectsOnlyConfiguredLegacyState() {
        XCTAssertEqual(
            GitConfigurator.removalSafety(hasManagedState: false, isConfigured: true),
            .legacyStateUnknown
        )
        XCTAssertEqual(
            GitConfigurator.removalSafety(hasManagedState: true, isConfigured: true),
            .safe
        )
        XCTAssertEqual(
            GitConfigurator.removalSafety(hasManagedState: false, isConfigured: false),
            .safe
        )
    }

    func testAgentConfAddsBothDirectivesToEmpty() {
        let body = GnuPGConfigurator.agentConfBody(existing: nil, wrapperPath: "/x/passeport-scd")
        XCTAssertTrue(body.contains("scdaemon-program /x/passeport-scd"))
        XCTAssertTrue(body.contains("enable-ssh-support"))
    }

    func testAgentConfIsIdempotent() {
        let first = GnuPGConfigurator.agentConfBody(existing: nil, wrapperPath: "/x/passeport-scd")
        let second = GnuPGConfigurator.agentConfBody(existing: first, wrapperPath: "/x/passeport-scd")
        XCTAssertEqual(first, second)
        XCTAssertEqual(second.components(separatedBy: "scdaemon-program").count - 1, 1)
        XCTAssertEqual(second.components(separatedBy: "enable-ssh-support").count - 1, 1)
    }

    func testAgentConfReplacesOldScdaemonLineAndPreservesOthers() {
        let existing = """
        # my config
        scdaemon-program /old/path
        default-cache-ttl 600
        """
        let body = GnuPGConfigurator.agentConfBody(existing: existing, wrapperPath: "/new/passeport-scd")
        XCTAssertFalse(body.contains("/old/path"))
        XCTAssertTrue(body.contains("scdaemon-program /new/passeport-scd"))
        XCTAssertTrue(body.contains("default-cache-ttl 600"))
        XCTAssertTrue(body.contains("# my config"))
    }

    func testStaleUserIDSelection() {
        let keep = "Alice <a@x>"
        // The stale one is picked, the kept one never is.
        XCTAssertEqual(
            GnuPGConfigurator.firstStaleUserIDIndex(uids: ["Old <a@x>", keep], keep: keep),
            0
        )
        XCTAssertEqual(
            GnuPGConfigurator.firstStaleUserIDIndex(uids: [keep, "Old <a@x>"], keep: keep),
            1
        )
    }

    func testStaleUserIDNeverPrunesLastOrMissingKeep() {
        let keep = "Alice <a@x>"
        // Only one UID: never prune (would leave the key with none).
        XCTAssertNil(GnuPGConfigurator.firstStaleUserIDIndex(uids: [keep], keep: keep))
        XCTAssertNil(GnuPGConfigurator.firstStaleUserIDIndex(uids: ["Old <a@x>"], keep: keep))
        // Kept UID not present (e.g. normalization mismatch): don't prune anything.
        XCTAssertNil(GnuPGConfigurator.firstStaleUserIDIndex(uids: ["X", "Y"], keep: keep))
    }
}

final class HexTests: XCTestCase {
    func testRoundTrip() {
        let data = Data([0x00, 0xff, 0xab, 0x10, 0x7e])
        XCTAssertEqual(Hex.encode(data), "00ffab107e")
        XCTAssertEqual(Hex.decode("00ffab107e"), data)
    }

    func testDecodeRejectsOddLengthAndNonHex() {
        XCTAssertNil(Hex.decode("abc"))
        XCTAssertNil(Hex.decode("zz"))
    }
}

final class SSHConfiguratorTests: XCTestCase {
    func testAddsManagedBlockWithoutDiscardingUserConfiguration() {
        let existing = "Host work\n  IdentityFile ~/.ssh/work\n"
        let body = SSHConfigurator.configBody(existing: existing, socketPath: "/tmp/passeport.sock")
        XCTAssertTrue(body.contains(existing.trimmingCharacters(in: .newlines)))
        XCTAssertTrue(body.contains("IdentityAgent \"/tmp/passeport.sock\""))
    }

    func testConfigurationIsIdempotentAndUpdatesSocket() {
        let first = SSHConfigurator.configBody(existing: nil, socketPath: "/tmp/old.sock")
        let second = SSHConfigurator.configBody(existing: first, socketPath: "/tmp/new.sock")
        XCTAssertFalse(second.contains("/tmp/old.sock"))
        XCTAssertEqual(second.components(separatedBy: "# Passeport ssh agent").count - 1, 1)
        XCTAssertEqual(second.components(separatedBy: "IdentityAgent").count - 1, 1)
    }

    func testEmptyConfigurationHasNoLeadingBlankLines() {
        let body = SSHConfigurator.configBody(existing: "\n\n", socketPath: "/tmp/p.sock")
        XCTAssertTrue(body.hasPrefix("# Passeport"))
        XCTAssertTrue(body.hasSuffix("\n"))
    }
}

final class ShellQuoteTests: XCTestCase {
    func testQuotesWhitespaceAndSingleQuotes() {
        XCTAssertEqual(ShellQuote.quote("plain"), "'plain'")
        XCTAssertEqual(ShellQuote.quote("a b"), "'a b'")
        XCTAssertEqual(ShellQuote.quote("it's"), "'it'\\''s'")
    }

    func testQuotePreventsShellExpansion() {
        XCTAssertEqual(ShellQuote.quote("$HOME; rm -rf /"), "'$HOME; rm -rf /'")
    }
}

final class IntegrationHealthTests: XCTestCase {
    func testTitlesDescribeEveryState() {
        XCTAssertEqual(IntegrationHealth.notConfigured.title, "Not configured")
        XCTAssertEqual(IntegrationHealth.working.title, "Installed")
        XCTAssertEqual(IntegrationHealth.broken("x").title, "Configured but broken")
    }
}
