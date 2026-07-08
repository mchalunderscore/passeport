import Foundation

enum CoreLocator {
    static func helperURL() throws -> URL {
        // The build phase copies the helper to Contents/Helpers, which is not
        // part of Contents/Resources and therefore invisible to
        // Bundle.url(forResource:withExtension:subdirectory:).
        let bundled = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/passeport-core")
        if FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }

        if let override = ProcessInfo.processInfo.environment["PASSEPORT_CORE_PATH"], !override.isEmpty {
            return URL(fileURLWithPath: override)
        }

        let candidates = [
            "crates/passeport-core/target/debug/passeport-core",
            "crates/passeport-core/target/release/passeport-core"
        ]

        let currentDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for candidate in candidates {
            let url = currentDirectory.appendingPathComponent(candidate)
            if FileManager.default.isExecutableFile(atPath: url.path) {
                return url
            }
        }

        throw PasseportError.helperMissing
    }
}
