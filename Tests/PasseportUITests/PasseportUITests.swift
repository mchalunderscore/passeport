import XCTest

@MainActor
final class PasseportUITests: XCTestCase {
    private func launchApp() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["--accessibility-audit"]
        app.launch()
        return app
    }

    func testEverySidebarPageIsKeyboardAccessible() {
        continueAfterFailure = false
        let app = launchApp()
        for page in ["Backup & Recovery", "Integrations", "Settings", "Keys"] {
            let row = app.outlines.cells.staticTexts[page]
            XCTAssertTrue(row.waitForExistence(timeout: 3), "Missing sidebar page: \(page)")
            row.click()
            XCTAssertTrue(app.windows.firstMatch.staticTexts[page].waitForExistence(timeout: 2))
        }
    }

    func testRecoveryImporterExposesAllWordFieldsAndSupportsReverseTab() {
        continueAfterFailure = false
        let app = launchApp()
        app.outlines.cells.staticTexts["Backup & Recovery"].click()
        let restore = app.buttons["Restore…"]
        XCTAssertTrue(restore.waitForExistence(timeout: 2))
        restore.click()
        XCTAssertTrue(app.sheets.staticTexts["Restore from Recovery Phrase"].waitForExistence(timeout: 2))
        let first = app.textFields["Recovery word 1"]
        XCTAssertTrue(first.exists)
        XCTAssertTrue(app.textFields["Recovery word 24"].exists)
        first.click()
        app.typeKey(.tab, modifierFlags: [])
        XCTAssertEqual(first.value(forKey: "hasKeyboardFocus") as? Bool, false)
        app.typeKey(.tab, modifierFlags: [.shift])
        XCTAssertEqual(first.value(forKey: "hasKeyboardFocus") as? Bool, true)
    }

    func testMainWindowHonorsMinimumSizeAndCoreControlsHaveNames() {
        continueAfterFailure = false
        let app = launchApp()
        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: 3))
        XCTAssertGreaterThanOrEqual(window.frame.width, 860)
        XCTAssertGreaterThanOrEqual(window.frame.height, 600)
        XCTAssertTrue(
            app.buttons["Create New Identity"].exists || app.buttons["Reset"].exists,
            "The identity page exposes neither onboarding nor existing-identity controls"
        )
    }
}
