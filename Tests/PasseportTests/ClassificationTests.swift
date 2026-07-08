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
}
