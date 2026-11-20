import AppKit
import Darwin
import Foundation

struct ClaudeDesktopItem: Identifiable, Equatable, Sendable {
    enum Category: String, Codable, Equatable, Sendable {
        case cacheAndCookies
        case appDataAndPrefs

        var label: String {
            switch self {
            case .cacheAndCookies: "缓存与 Cookie"
            case .appDataAndPrefs: "配置与登录数据"
            }
        }
    }

    let id: String
    let title: String
    let relativePath: String
    let fullPath: String
    let category: Category
    let exists: Bool
    let sizeBytes: Int64
}

struct ClaudeDesktopInventory: Equatable, Sendable {
    let installed: Bool
    let appPath: String?
    let executablePath: String?
    let version: String?
    let running: Bool
    let items: [ClaudeDesktopItem]
    let isolatedProfileBytes: Int64

    var existingItems: [ClaudeDesktopItem] {
        items.filter(\.exists)
    }

    var totalBytes: Int64 {
        existingItems.reduce(0) { $0 + $1.sizeBytes }
    }
}

enum PathSafety {
    /// Verifies that `target` lies strictly inside `root` and that NO component from `root` down to `target`
    /// (inclusive) is a symbolic link. Prevents symlink traversal before moving items to Trash.
    static func verifyNoSymlinks(at target: URL, within root: URL) throws {
        let normalizedRoot = root.standardizedFileURL.resolvingSymlinksInPath()
        let rootComponents = normalizedRoot.pathComponents
        let targetComponents = target.standardizedFileURL.pathComponents

        guard targetComponents.count > rootComponents.count,
              Array(targetComponents.prefix(rootComponents.count)) == rootComponents else {
            throw WorkbenchError.unsafeSymlinkPath(target.path)
        }

        var cursor = normalizedRoot
        for component in targetComponents.dropFirst(rootComponents.count) {
            cursor.appendPathComponent(component)
            var st = stat()
            if lstat(cursor.path, &st) != 0 {
                if errno == ENOENT { break }
                throw WorkbenchError.unsafeSymlinkPath(cursor.path)
            }
            if (st.st_mode & S_IFMT) == S_IFLNK {
                throw WorkbenchError.unsafeSymlinkPath(cursor.path)
            }
        }
    }

    static func directoryByteSize(at url: URL) -> Int64 {
        var st = stat()
        guard lstat(url.path, &st) == 0 else { return 0 }
        let kind = st.st_mode & S_IFMT
        if kind == S_IFREG {
            return Int64(st.st_size)
        }
        guard kind == S_IFDIR else { return 0 }
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
            options: [.skipsPackageDescendants]
        ) else {
            return 0
        }
        var total: Int64 = 0
        for case let fileURL as URL in enumerator {
            guard let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]),
                  values.isSymbolicLink != true,
                  values.isRegularFile == true,
                  let size = values.fileSize else {
                continue
            }
            total += Int64(size)
        }
        return total
    }
}

enum ClaudeDesktopManager {
    static let bundleIdentifier = "com.anthropic.claudefordesktop"

    private static let itemSpecs: [(id: String, title: String, rel: String, category: ClaudeDesktopItem.Category)] = [
        ("app-support", "主数据与账号状态", "Library/Application Support/Claude", .appDataAndPrefs),
        ("preferences", "偏好设置 Plist", "Library/Preferences/com.anthropic.claudefordesktop.plist", .appDataAndPrefs),
        ("saved-state", "窗口恢复状态", "Library/Saved Application State/com.anthropic.claudefordesktop.savedState", .cacheAndCookies),
        ("cache-dir", "应用缓存 (Claude)", "Library/Caches/Claude", .cacheAndCookies),
        ("cache-bundle", "Bundle 缓存", "Library/Caches/com.anthropic.claudefordesktop", .cacheAndCookies),
        ("webkit", "WebKit 本地存储", "Library/WebKit/com.anthropic.claudefordesktop", .cacheAndCookies),
        ("http-storage", "HTTPStorages Cookie", "Library/HTTPStorages/com.anthropic.claudefordesktop", .cacheAndCookies),
        ("binary-cookies", "旧版 BinaryCookies", "Library/HTTPStorages/com.anthropic.claudefordesktop.binarycookies", .cacheAndCookies),
        ("logs", "应用运行日志", "Library/Logs/Claude", .cacheAndCookies),
    ]

    static func isolatedDesktopProfileURL(stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory()) -> URL {
        stateDirectory.appendingPathComponent("isolated-claude-desktop", isDirectory: true)
    }

    @MainActor
    static func inspect(home: URL = FileManager.default.homeDirectoryForCurrentUser) async -> ClaudeDesktopInventory {
        let running = !NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier).isEmpty
        let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleIdentifier)
        let bundle = appURL.flatMap { Bundle(url: $0) }
        let version = bundle?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        let execName = bundle?.object(forInfoDictionaryKey: "CFBundleExecutable") as? String
        let execPath = appURL.flatMap { url -> String? in
            guard let execName, !execName.isEmpty else { return nil }
            let path = url.appendingPathComponent("Contents/MacOS/\(execName)").path
            return FileManager.default.isExecutableFile(atPath: path) ? path : nil
        }

        return await Task.detached(priority: .userInitiated) {
            let items: [ClaudeDesktopItem] = itemSpecs.map { spec in
                let fullURL = home.appendingPathComponent(spec.rel)
                var st = stat()
                let exists = lstat(fullURL.path, &st) == 0
                let bytes = exists ? PathSafety.directoryByteSize(at: fullURL) : 0
                return ClaudeDesktopItem(
                    id: spec.id,
                    title: spec.title,
                    relativePath: "~/\(spec.rel)",
                    fullPath: fullURL.path,
                    category: spec.category,
                    exists: exists,
                    sizeBytes: bytes
                )
            }
            let isolatedBytes = PathSafety.directoryByteSize(at: isolatedDesktopProfileURL())
            return ClaudeDesktopInventory(
                installed: appURL != nil,
                appPath: appURL?.path,
                executablePath: execPath,
                version: version?.isEmpty == false ? version : nil,
                running: running,
                items: items,
                isolatedProfileBytes: isolatedBytes
            )
        }.value
    }

    @MainActor
    static func terminateRunningDesktop() -> Bool {
        let apps = NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier)
        guard !apps.isEmpty else { return true }
        for app in apps {
            _ = app.terminate()
        }
        return true
    }

    /// Safely moves selected Claude Desktop items to macOS Trash (100% recoverable, never `rm -rf`).
    /// Refuses while Claude Desktop is running or if any symlink exists along the path.
    static func trashItems(
        _ selected: [ClaudeDesktopItem],
        requireNotRunning: Bool = true,
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) async throws -> Int {
        if requireNotRunning {
            let isRunning = await MainActor.run {
                !NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier).isEmpty
            }
            if isRunning {
                throw WorkbenchError.processAlreadyRunning("Claude Desktop")
            }
        }
        return try await Task.detached(priority: .userInitiated) {
            let fm = FileManager.default
            var moved = 0
            for item in selected where item.exists {
                let url = URL(fileURLWithPath: item.fullPath)
                guard fm.fileExists(atPath: url.path) else { continue }
                try PathSafety.verifyNoSymlinks(at: url, within: home)
                try fm.trashItem(at: url, resultingItemURL: nil)
                moved += 1
            }
            return moved
        }.value
    }

    struct DesktopLaunchSpec: Equatable, Sendable {
        let arguments: [String]
        let environment: [String: String]
        let isolatedProfilePath: String?
        let language: String?
    }

    static func buildLaunchSpec(
        proxyPort: Int?,
        countryCode: String?,
        geoTimeZone: String?,
        useIsolatedProfile: Bool,
        stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory()
    ) -> DesktopLaunchSpec {
        var args: [String] = [
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ]
        var isolatedPath: String?
        if useIsolatedProfile {
            let dir = isolatedDesktopProfileURL(stateDirectory: stateDirectory)
            isolatedPath = dir.path
            args.append("--user-data-dir=\(dir.path)")
        }

        var env = ProcessInfo.processInfo.environment
        var bcp47Lang: String?
        if let countryCode {
            let profile = ClaudeRegions.recommendedProcessLocale(countryCode: countryCode, geoTimeZone: geoTimeZone)
            env["TZ"] = profile.timeZone
            env["LANG"] = profile.lang
            env["LC_ALL"] = profile.lang
            let bcp47 = IsolatedBrowserLauncher.bcp47Tag(fromPOSIX: profile.lang)
            bcp47Lang = bcp47
            env["LANGUAGE"] = IsolatedBrowserLauncher.acceptLanguagesValue(for: bcp47).replacingOccurrences(of: ",", with: ":")
            args.append("--lang=\(bcp47)")
        }
        if let proxyPort, (1...65535).contains(proxyPort) {
            let proxyURL = "http://127.0.0.1:\(proxyPort)"
            // Lock both Chromium renderer (--proxy-server) and Electron Node main process (HTTP_PROXY/NODE_USE_ENV_PROXY)
            args.append("--proxy-server=\(proxyURL)")
            env["HTTP_PROXY"] = proxyURL
            env["HTTPS_PROXY"] = proxyURL
            env["ALL_PROXY"] = proxyURL
            env["http_proxy"] = proxyURL
            env["https_proxy"] = proxyURL
            env["NODE_USE_ENV_PROXY"] = "1"
        }

        return DesktopLaunchSpec(
            arguments: args,
            environment: env,
            isolatedProfilePath: isolatedPath,
            language: bcp47Lang
        )
    }

    /// Launches macOS Claude Desktop with Chromium + Node proxy locking, anti-QUIC/WebRTC flags,
    /// process-level TZ/LANG alignment, and optional isolated `--user-data-dir` (zero global macOS timezone mutation).
    @MainActor
    static func launchAligned(
        inventory: ClaudeDesktopInventory,
        proxyPort: Int?,
        countryCode: String?,
        geoTimeZone: String?,
        useIsolatedProfile: Bool,
        stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory()
    ) throws -> Process {
        guard let execPath = inventory.executablePath else {
            throw WorkbenchError.executableMissing("Claude.app")
        }
        if !useIsolatedProfile && inventory.running {
            throw WorkbenchError.processAlreadyRunning("Claude Desktop")
        }

        let spec = buildLaunchSpec(
            proxyPort: proxyPort,
            countryCode: countryCode,
            geoTimeZone: geoTimeZone,
            useIsolatedProfile: useIsolatedProfile,
            stateDirectory: stateDirectory
        )
        if let isolatedPath = spec.isolatedProfilePath {
            let dir = URL(fileURLWithPath: isolatedPath, isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            if let lang = spec.language {
                try IsolatedBrowserLauncher.applyProfileLanguagePreferences(profileDirectory: dir, bcp47Language: lang)
            }
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: execPath)
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
}
