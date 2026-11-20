import AppKit
import Darwin
import Foundation

enum ProxyScriptTarget: String, CaseIterable, Identifiable, Sendable {
    case clashVergeRev
    case clashVergeLegacy
    case mihomoParty
    case flClash

    var id: Self { self }

    var displayName: String {
        switch self {
        case .clashVergeRev: "Clash Verge Rev"
        case .clashVergeLegacy: "Clash Verge (旧版)"
        case .mihomoParty: "Mihomo Party"
        case .flClash: "FlClash"
        }
    }

    var relativeConfigDir: String {
        switch self {
        case .clashVergeRev: "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"
        case .clashVergeLegacy: "Library/Application Support/io.github.zzzgydi.clash-verge"
        case .mihomoParty: "Library/Application Support/mihomo-party"
        case .flClash: "Library/Application Support/com.follow.clash"
        }
    }

    var relativeScriptPath: String {
        switch self {
        case .clashVergeRev, .clashVergeLegacy: "profiles/Script.js"
        case .mihomoParty: "override/claude-env-guard.js"
        case .flClash: "claude-env-override.js"
        }
    }

    var reloadHint: String {
        switch self {
        case .clashVergeRev, .clashVergeLegacy:
            "在软件的「订阅/配置」页面点击刷新或重选当前订阅即可使全局扩展脚本生效。"
        case .mihomoParty:
            "脚本已写入 Mihomo Party 的 override/claude-env-guard.js，在「覆写」页勾选启用并重载订阅即可生效。"
        case .flClash:
            "脚本已写入 FlClash 配置目录（claude-env-override.js），在 FlClash「脚本/覆写」页导入启用即可生效。"
        }
    }

    var backupFileName: String {
        switch self {
        case .clashVergeRev: "clash-verge-script-backup.json"
        case .clashVergeLegacy: "clash-verge-legacy-script-backup.json"
        case .mihomoParty: "mihomo-party-script-backup.json"
        case .flClash: "flclash-script-backup.json"
        }
    }

    var appBundleCandidates: (paths: [String], bundleIDs: [String]) {
        switch self {
        case .clashVergeRev, .clashVergeLegacy:
            return (["/Applications/Clash Verge.app"], ["io.github.clash-verge-rev.clash-verge-rev", "io.github.zzzgydi.clash-verge"])
        case .mihomoParty:
            return (["/Applications/Mihomo Party.app", "/Applications/Clash Party.app"], ["org.mihomo.party"])
        case .flClash:
            return (["/Applications/FlClash.app"], ["com.follow.clash"])
        }
    }

    func configDirURL(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent(relativeConfigDir, isDirectory: true)
    }

    func scriptURL(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        configDirURL(home: home).appendingPathComponent(relativeScriptPath)
    }

    func backupFileURL(stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory()) -> URL {
        stateDirectory.appendingPathComponent(backupFileName)
    }
}

enum ClashScriptStatus: Equatable, Sendable {
    case vergeNotInstalled
    case notInstalled(hasExistingCustomScript: Bool)
    case installed(chainedCustomScript: Bool, activeInKernel: Bool)
}

enum ClashScriptError: LocalizedError {
    case vergeDirectoryMissing
    case unsafeFile(String)
    case backupMissing
    case backupCorrupted
    case busy

    var errorDescription: String? {
        switch self {
        case .vergeDirectoryMissing:
            "未找到 Clash Verge Rev 配置目录（~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev）。"
        case .unsafeFile(let path):
            "检测到符号链接或非普通文件，已拒绝修改：\(path)"
        case .backupMissing:
            "未找到原始 Script.js 备份文件。"
        case .backupCorrupted:
            "备份文件损坏，为安全起见未覆盖现有 Script.js。"
        case .busy:
            "另一个操作正在修改 Clash Verge 脚本，请稍后重试。"
        }
    }
}

/// Safe, atomic, reversible 1-click installer for Clash Verge Rev's Global Extend Script (`profiles/Script.js`).
/// Never deletes user scripts: backs up original bytes first and chains custom user `main()` if present.
enum ClashVergeScriptInstaller {
    static let managedMarkerStart = "// [CLAUDE-ENV-CHECK-MANAGED-START]"
    static let managedMarkerEnd = "// [CLAUDE-ENV-CHECK-MANAGED-END]"

    private struct ScriptBackup: Codable, Sendable {
        let version: Int
        let targetPath: String
        let hadFile: Bool
        let originalBase64: String
        let chainedCustomScript: Bool
        let savedAt: Date
    }

    static func defaultVergeDir(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent(
            "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev", isDirectory: true
        )
    }

    static func defaultBackupFile(stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory()) -> URL {
        stateDirectory.appendingPathComponent("clash-verge-script-backup.json")
    }

    static func scriptFileURL(vergeDir: URL) -> URL {
        vergeDir.appendingPathComponent("profiles/Script.js")
    }

    static func inspectStatus(
        vergeDir: URL = defaultVergeDir(),
        backupFile: URL = defaultBackupFile(),
        liveSnapshot: ClashControllerSnapshot? = nil
    ) -> ClashScriptStatus {
        let fm = FileManager.default
        guard fm.fileExists(atPath: vergeDir.path) else {
            return .vergeNotInstalled
        }
        let target = scriptFileURL(vergeDir: vergeDir)
        let currentText = (try? String(contentsOf: target, encoding: .utf8)) ?? ""
        if currentText.contains(managedMarkerStart) {
            let chained = (try? readBackup(at: backupFile))?.chainedCustomScript ?? false
            let liveActive = liveSnapshot?.selectorGroups.contains(where: { $0.name == "Claude-Pin" }) ?? false
            return .installed(chainedCustomScript: chained, activeInKernel: liveActive)
        }
        let isCustom = !currentText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !isDefaultStubScript(currentText)
        return .notInstalled(hasExistingCustomScript: isCustom)
    }

    static func discoverInstalledTargets(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [ProxyScriptTarget] {
        let fm = FileManager.default
        return ProxyScriptTarget.allCases.filter { fm.fileExists(atPath: $0.configDirURL(home: home).path) }
    }

    static func inspectStatus(
        target: ProxyScriptTarget,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory(),
        liveSnapshot: ClashControllerSnapshot? = nil
    ) -> ClashScriptStatus {
        let fm = FileManager.default
        let configDir = target.configDirURL(home: home)
        guard fm.fileExists(atPath: configDir.path) else {
            return .vergeNotInstalled
        }
        let scriptURL = target.scriptURL(home: home)
        let backupURL = target.backupFileURL(stateDirectory: stateDirectory)
        let currentText = (try? String(contentsOf: scriptURL, encoding: .utf8)) ?? ""
        if currentText.contains(managedMarkerStart) {
            let chained = (try? readBackup(at: backupURL))?.chainedCustomScript ?? false
            let liveActive = liveSnapshot?.selectorGroups.contains(where: { $0.name == "Claude-Pin" }) ?? false
            return .installed(chainedCustomScript: chained, activeInKernel: liveActive)
        }
        let isCustom = !currentText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !isDefaultStubScript(currentText)
        return .notInstalled(hasExistingCustomScript: isCustom)
    }

    static func install(
        target: ProxyScriptTarget,
        preferredNodeName: String? = nil,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory()
    ) throws -> Bool {
        let configDir = target.configDirURL(home: home)
        let scriptURL = target.scriptURL(home: home)
        let backupURL = target.backupFileURL(stateDirectory: stateDirectory)
        return try installToFile(
            configDir: configDir,
            targetFile: scriptURL,
            backupFile: backupURL,
            preferredNodeName: preferredNodeName,
            home: home
        )
    }

    static func restore(
        target: ProxyScriptTarget,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        stateDirectory: URL = IsolatedBrowserLauncher.defaultStateDirectory()
    ) throws {
        try restoreFromBackup(
            backupFile: target.backupFileURL(stateDirectory: stateDirectory),
            isStandaloneOverride: (target == .mihomoParty || target == .flClash),
            home: home
        )
    }

    @MainActor
    static func openClientApp(_ target: ProxyScriptTarget) {
        let homeApps = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications")
        let info = target.appBundleCandidates
        for p in info.paths {
            if FileManager.default.fileExists(atPath: p) {
                NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: p), configuration: NSWorkspace.OpenConfiguration())
                return
            }
            let userApp = homeApps.appendingPathComponent(URL(fileURLWithPath: p).lastPathComponent).path
            if FileManager.default.fileExists(atPath: userApp) {
                NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: userApp), configuration: NSWorkspace.OpenConfiguration())
                return
            }
        }
        for bid in info.bundleIDs {
            if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bid) {
                NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
                return
            }
        }
    }

    static func install(
        preferredNodeName: String? = nil,
        vergeDir: URL = defaultVergeDir(),
        backupFile: URL = defaultBackupFile(),
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) throws -> Bool {
        try installToFile(
            configDir: vergeDir,
            targetFile: scriptFileURL(vergeDir: vergeDir),
            backupFile: backupFile,
            preferredNodeName: preferredNodeName,
            home: home
        )
    }

    private static func installToFile(
        configDir: URL,
        targetFile: URL,
        backupFile: URL,
        preferredNodeName: String?,
        home: URL
    ) throws -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: configDir.path) else {
            throw ClashScriptError.vergeDirectoryMissing
        }
        let lockFD = try acquireLock(near: backupFile)
        defer { _ = close(lockFD) }

        try fm.createDirectory(at: targetFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try verifySafeTarget(targetFile, within: home)

        let existingBytes = try readRegularFileIfExists(targetFile)
        let existingText = existingBytes.flatMap { String(data: $0, encoding: .utf8) } ?? ""

        let originalTextForChaining: String
        let isCustomUserScript: Bool

        if let existingBackup = try readBackup(at: backupFile) {
            let origData = Data(base64Encoded: existingBackup.originalBase64) ?? Data()
            originalTextForChaining = String(data: origData, encoding: .utf8) ?? ""
            isCustomUserScript = existingBackup.chainedCustomScript
        } else {
            let alreadyManaged = existingText.contains(managedMarkerStart)
            isCustomUserScript = !alreadyManaged
                && !existingText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && !isDefaultStubScript(existingText)
            originalTextForChaining = existingText

            let backup = ScriptBackup(
                version: 1,
                targetPath: targetFile.path,
                hadFile: existingBytes != nil,
                originalBase64: (existingBytes ?? Data()).base64EncodedString(),
                chainedCustomScript: isCustomUserScript,
                savedAt: Date()
            )
            let backupBytes = try JSONEncoder().encode(backup)
            try fm.createDirectory(at: backupFile.deletingLastPathComponent(),
                                   withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
            try atomicWrite(backupBytes, to: backupFile, mode: 0o600)
        }

        let finalScript = composeScript(
            preferredNodeName: preferredNodeName,
            customOriginalScript: isCustomUserScript ? originalTextForChaining : nil
        )
        try atomicWrite(Data(finalScript.utf8), to: targetFile, mode: 0o644)
        return isCustomUserScript
    }

    /// Restores the exact original `profiles/Script.js` saved prior to 1-click injection and removes the backup.
    static func restore(
        vergeDir: URL = defaultVergeDir(),
        backupFile: URL = defaultBackupFile(),
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) throws {
        _ = vergeDir
        try restoreFromBackup(backupFile: backupFile, isStandaloneOverride: false, home: home)
    }

    private static func restoreFromBackup(
        backupFile: URL,
        isStandaloneOverride: Bool,
        home: URL
    ) throws {
        let lockFD = try acquireLock(near: backupFile)
        defer { _ = close(lockFD) }

        guard let backup = try readBackup(at: backupFile) else {
            throw ClashScriptError.backupMissing
        }
        guard let originalData = Data(base64Encoded: backup.originalBase64) else {
            throw ClashScriptError.backupCorrupted
        }
        let target = URL(fileURLWithPath: backup.targetPath)
        try verifySafeTarget(target, within: home)

        if backup.hadFile {
            try atomicWrite(originalData, to: target, mode: 0o644)
        } else if isStandaloneOverride {
            try? FileManager.default.removeItem(at: target)
        } else {
            let stub = "// Define main function (script entry)\n\nfunction main(config, profileName) {\n  return config;\n}\n"
            try atomicWrite(Data(stub.utf8), to: target, mode: 0o644)
        }
        try? FileManager.default.removeItem(at: backupFile)
    }

    @MainActor
    static func openClashVergeApp() {
        let candidates = [
            "/Applications/Clash Verge.app",
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Clash Verge.app").path,
        ]
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: path), configuration: NSWorkspace.OpenConfiguration())
            return
        }
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "io.github.clash-verge-rev.clash-verge-rev") {
            NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
        }
    }

    // MARK: - Script Composition & Helpers

    static func isDefaultStubScript(_ text: String) -> Bool {
        // Strip single-line comments & whitespace; default Clash Verge stub is `function main(config, profileName) { return config; }`
        let withoutComments = text
            .split(whereSeparator: \.isNewline)
            .map { line -> String in
                if let range = line.range(of: "//") {
                    return String(line[..<range.lowerBound])
                }
                return String(line)
            }
            .joined(separator: " ")
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        return withoutComments == "function main(config, profileName) { return config; }"
            || withoutComments == "function main(config) { return config; }"
            || withoutComments == "function main(config, profileName) { return config }"
            || withoutComments == "function main(config) { return config }"
    }

    static func composeScript(preferredNodeName: String?, customOriginalScript: String?) -> String {
        let coreBody = ClashOverrideGenerator.generateVergeJavaScript(
            preferredNodeName: preferredNodeName,
            entryFunctionName: customOriginalScript == nil ? "main" : "__claudeEnvGuardApply"
        )

        guard let customOriginalScript, !customOriginalScript.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return """
\(managedMarkerStart)
\(coreBody)
\(managedMarkerEnd)
"""
        }

        // Preserve user's original script by scoping its `main` inside an IIFE and chaining our anti-leak transform after it.
        return """
\(managedMarkerStart)
// 已自动保留你原有的 Clash Verge 全局扩展脚本，并在其后串联 Claude 防泄漏加固。

const __claudeOriginalUserMain = (function () {
\(customOriginalScript)
  return typeof main === "function" ? main : (c) => c;
})();

\(coreBody)

function main(config, profileName) {
  const afterUser = __claudeOriginalUserMain(config, profileName) || config;
  return __claudeEnvGuardApply(afterUser, profileName);
}
\(managedMarkerEnd)
"""
    }

    private static func readBackup(at url: URL) throws -> ScriptBackup? {
        guard let data = try readRegularFileIfExists(url) else { return nil }
        guard let decoded = try? JSONDecoder().decode(ScriptBackup.self, from: data),
              decoded.version == 1,
              decoded.targetPath.hasPrefix("/"),
              URL(fileURLWithPath: decoded.targetPath).lastPathComponent.hasSuffix(".js") else {
            throw ClashScriptError.backupCorrupted
        }
        return decoded
    }

    private static func verifySafeTarget(_ target: URL, within home: URL) throws {
        do {
            try PathSafety.verifyNoSymlinks(at: target, within: home)
        } catch {
            throw ClashScriptError.unsafeFile(target.path)
        }
        var st = stat()
        if lstat(target.path, &st) == 0 {
            guard (st.st_mode & S_IFMT) == S_IFREG else {
                throw ClashScriptError.unsafeFile(target.path)
            }
        }
    }

    private static func readRegularFileIfExists(_ url: URL) throws -> Data? {
        var st = stat()
        if lstat(url.path, &st) != 0 {
            if errno == ENOENT { return nil }
            throw ClashScriptError.unsafeFile(url.path)
        }
        guard (st.st_mode & S_IFMT) == S_IFREG else {
            throw ClashScriptError.unsafeFile(url.path)
        }
        return try Data(contentsOf: url)
    }

    private static func acquireLock(near backupFile: URL) throws -> Int32 {
        let dir = backupFile.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let lockPath = dir.appendingPathComponent("clash-script.lock").path
        let fd = open(lockPath, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { throw ClashScriptError.unsafeFile(lockPath) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            let err = errno
            _ = close(fd)
            if err == EWOULDBLOCK { throw ClashScriptError.busy }
            throw ClashScriptError.unsafeFile(lockPath)
        }
        return fd
    }

    private static func atomicWrite(_ data: Data, to url: URL, mode: mode_t) throws {
        let template = url.deletingLastPathComponent()
            .appendingPathComponent(".claude-verge-script.XXXXXXXX").path
        var path = template.utf8CString
        let fd = path.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard fd >= 0 else { throw ClashScriptError.unsafeFile(url.path) }
        let tempPath = String(decoding: path.dropLast().map { UInt8(bitPattern: $0) }, as: UTF8.self)
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer {
            try? handle.close()
            _ = unlink(tempPath)
        }
        try handle.write(contentsOf: data)
        _ = fchmod(fd, mode)
        try handle.synchronize()
        guard rename(tempPath, url.path) == 0 else {
            throw ClashScriptError.unsafeFile(url.path)
        }
    }
}
