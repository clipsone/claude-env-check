import AppKit
import Foundation

struct DiscoveredBrowser: Identifiable, Equatable, Sendable {
    let id: String
    let name: String
    let bundleID: String
    let appPath: String
    let executablePath: String
    let version: String?
}

struct IsolatedLaunchSpec: Equatable, Sendable {
    let executablePath: String
    let arguments: [String]
    let environment: [String: String]
    let profileDirectory: String
    let proxyPort: Int?
    let timeZone: String?
    let language: String?
}

enum WorkbenchError: LocalizedError {
    case browserNotFound
    case executableMissing(String)
    case unsafeSymlinkPath(String)
    case processAlreadyRunning(String)
    case launchFailed(String)

    var errorDescription: String? {
        switch self {
        case .browserNotFound: "未找到已安装的 Chromium 系浏览器（Chrome / Brave / Edge / Vivaldi）。"
        case .executableMissing(let path): "找不到可执行文件：\(path)"
        case .unsafeSymlinkPath(let path): "检测到符号链接路径，出于安全已拒绝操作：\(path)"
        case .processAlreadyRunning(let name): "\(name) 当前正在运行，请先退出后再操作。"
        case .launchFailed(let detail): "启动失败：\(detail)"
        }
    }
}

enum IsolatedBrowserLauncher {
    private static let supportedBrowsers: [(id: String, name: String, bundleID: String, fallbackApp: String)] = [
        ("chrome", "Google Chrome", "com.google.Chrome", "/Applications/Google Chrome.app"),
        ("brave", "Brave Browser", "com.brave.Browser", "/Applications/Brave Browser.app"),
        ("edge", "Microsoft Edge", "com.microsoft.edgemac", "/Applications/Microsoft Edge.app"),
        ("vivaldi", "Vivaldi", "com.vivaldi.Vivaldi", "/Applications/Vivaldi.app"),
        ("chromium", "Chromium", "org.chromium.Chromium", "/Applications/Chromium.app"),
    ]

    @MainActor
    static func discoverBrowsers() -> [DiscoveredBrowser] {
        let fm = FileManager.default
        var found: [DiscoveredBrowser] = []

        for item in supportedBrowsers {
            let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: item.bundleID)
                ?? (fm.fileExists(atPath: item.fallbackApp) ? URL(fileURLWithPath: item.fallbackApp) : nil)
            guard let appURL,
                  let bundle = Bundle(url: appURL),
                  let execName = bundle.object(forInfoDictionaryKey: "CFBundleExecutable") as? String,
                  !execName.isEmpty else {
                continue
            }
            let execURL = appURL.appendingPathComponent("Contents/MacOS/\(execName)")
            guard fm.isExecutableFile(atPath: execURL.path) else { continue }
            let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            found.append(DiscoveredBrowser(
                id: item.id,
                name: item.name,
                bundleID: item.bundleID,
                appPath: appURL.path,
                executablePath: execURL.path,
                version: version?.isEmpty == false ? version : nil
            ))
        }
        return found
    }

    static func profileDirectory(
        browserID: String,
        stateDirectory: URL = defaultStateDirectory()
    ) -> URL {
        stateDirectory
            .appendingPathComponent("isolated-browser-profiles", isDirectory: true)
            .appendingPathComponent(browserID, isDirectory: true)
    }

    static func defaultStateDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
            "Library/Application Support/local.claude-environment-check", isDirectory: true
        )
    }

    /// Builds launch arguments & process-level environment for an isolated Chromium workbench.
    /// Deliberately never copies daily browser bookmarks, cookies, or extensions, and never mutates macOS global timezone.
    static func buildLaunchSpec(
        browser: DiscoveredBrowser,
        proxyPort: Int?,
        countryCode: String?,
        geoTimeZone: String?,
        startURL: String = "https://claude.ai",
        stateDirectory: URL = defaultStateDirectory()
    ) -> IsolatedLaunchSpec {
        let profileURL = profileDirectory(browserID: browser.id, stateDirectory: stateDirectory)
        let localeProfile = countryCode.map {
            ClaudeRegions.recommendedProcessLocale(countryCode: $0, geoTimeZone: geoTimeZone)
        }
        let bcp47Lang = localeProfile.map { bcp47Tag(fromPOSIX: $0.lang) }

        var args: [String] = [
            "--user-data-dir=\(profileURL.path)",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ]

        if let bcp47Lang {
            args.append("--lang=\(bcp47Lang)")
        }

        if let proxyPort, (1...65535).contains(proxyPort) {
            // HTTP CONNECT already resolves hostnames remotely on the proxy; omitting --host-resolver-rules
            // avoids Chrome's "unsupported command-line flag" infobar without weakening DNS protection.
            args.append("--proxy-server=http://127.0.0.1:\(proxyPort)")
        }

        let trimmedURL = startURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedURL.hasPrefix("https://") || trimmedURL.hasPrefix("http://") || trimmedURL == "about:blank" {
            args.append(trimmedURL)
        } else {
            args.append("https://claude.ai")
        }

        var env = ProcessInfo.processInfo.environment
        if let localeProfile {
            env["TZ"] = localeProfile.timeZone
            env["LANG"] = localeProfile.lang
            env["LC_ALL"] = localeProfile.lang
            if let bcp47Lang {
                env["LANGUAGE"] = acceptLanguagesValue(for: bcp47Lang).replacingOccurrences(of: ",", with: ":")
            }
        }
        if let proxyPort, (1...65535).contains(proxyPort) {
            let proxyURL = "http://127.0.0.1:\(proxyPort)"
            env["HTTP_PROXY"] = proxyURL
            env["HTTPS_PROXY"] = proxyURL
            env["http_proxy"] = proxyURL
            env["https_proxy"] = proxyURL
        }

        return IsolatedLaunchSpec(
            executablePath: browser.executablePath,
            arguments: args,
            environment: env,
            profileDirectory: profileURL.path,
            proxyPort: proxyPort,
            timeZone: localeProfile?.timeZone,
            language: bcp47Lang
        )
    }

    static func launch(spec: IsolatedLaunchSpec) throws -> Process {
        let fm = FileManager.default
        guard fm.isExecutableFile(atPath: spec.executablePath) else {
            throw WorkbenchError.executableMissing(spec.executablePath)
        }
        let profileURL = URL(fileURLWithPath: spec.profileDirectory, isDirectory: true)
        try fm.createDirectory(at: profileURL, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        if let lang = spec.language {
            try applyProfileLanguagePreferences(profileDirectory: profileURL, bcp47Language: lang)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: spec.executablePath)
        process.arguments = spec.arguments
        process.environment = spec.environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            return process
        } catch {
            throw WorkbenchError.launchFailed(error.localizedDescription)
        }
    }

    static func profileSizeBytes(browserID: String, stateDirectory: URL = defaultStateDirectory()) -> Int64 {
        let url = profileDirectory(browserID: browserID, stateDirectory: stateDirectory)
        return PathSafety.directoryByteSize(at: url)
    }

    static func trashProfile(
        browserID: String,
        stateDirectory: URL = defaultStateDirectory(),
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) throws {
        let url = profileDirectory(browserID: browserID, stateDirectory: stateDirectory)
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        try PathSafety.verifyNoSymlinks(at: url, within: home)
        try FileManager.default.trashItem(at: url, resultingItemURL: nil)
    }

    static func bcp47Tag(fromPOSIX lang: String) -> String {
        let base = lang.split(separator: ".").first.map(String.init) ?? lang
        return base.replacingOccurrences(of: "_", with: "-")
    }

    static func acceptLanguagesValue(for bcp47: String) -> String {
        let parts = bcp47.split(separator: "-")
        if parts.count >= 2 {
            let prefix = String(parts[0])
            if prefix.caseInsensitiveCompare(bcp47) != .orderedSame {
                return "\(bcp47),\(prefix)"
            }
        }
        return bcp47
    }

    /// Merges `intl.accept_languages` / `intl.selected_languages` into the isolated profile's `Default/Preferences`
    /// so `navigator.language`, `navigator.languages`, and `Accept-Language` align with the exit region on macOS
    /// without mutating system language or triggering Chrome infobars.
    static func applyProfileLanguagePreferences(profileDirectory: URL, bcp47Language: String) throws {
        let fm = FileManager.default
        let defaultDir = profileDirectory.appendingPathComponent("Default", isDirectory: true)
        try fm.createDirectory(at: defaultDir, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let prefsURL = defaultDir.appendingPathComponent("Preferences")
        var root: [String: Any] = [:]
        if let existing = try? Data(contentsOf: prefsURL),
           let parsed = try? JSONSerialization.jsonObject(with: existing) as? [String: Any] {
            root = parsed
        }
        var intl = (root["intl"] as? [String: Any]) ?? [:]
        let accept = acceptLanguagesValue(for: bcp47Language)
        intl["accept_languages"] = accept
        intl["selected_languages"] = accept
        root["intl"] = intl
        let encoded = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        try encoded.write(to: prefsURL, options: .atomic)
    }
}
