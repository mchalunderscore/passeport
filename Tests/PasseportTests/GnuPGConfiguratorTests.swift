import XCTest
@testable import Passeport

final class GnuPGConfiguratorTests: XCTestCase {
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
