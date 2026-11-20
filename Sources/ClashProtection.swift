import Darwin
import Foundation

enum Clash {
    static func proxyURL(_ port: Int) -> String { "http://127.0.0.1:\(port)" }

    static func validPort(_ text: String) -> Int? {
        guard let port = Int(text.trimmingCharacters(in: .whitespacesAndNewlines)),
              (1...65535).contains(port) else { return nil }
        return port
    }

    static func detectedPort(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> Int? {
        let config = home.appendingPathComponent(
            "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev", isDirectory: true
        )
        let sources = [("clash-verge.yaml", "mixed-port"), ("verge.yaml", "verge_mixed_port")]
        for (file, key) in sources {
            guard let text = try? String(contentsOf: config.appendingPathComponent(file), encoding: .utf8) else {
                continue
            }
            for line in text.split(whereSeparator: \.isNewline) where line.hasPrefix(key + ":") {
                let raw = line.dropFirst(key.count + 1).prefix(while: { $0 != "#" })
                let value = raw.trimmingCharacters(in: .whitespaces)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                return validPort(value)
            }
        }
        return nil
    }

    static func probe(port: Int) throws -> Int {
        guard (1...65535).contains(port) else { throw ProtectionError.invalidPort }
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.environment = ["LC_ALL": "C"]
        process.arguments = [
            "-q", "--silent", "--connect-timeout", "3", "--max-time", "8",
            "--proxy", proxyURL(port), "--noproxy", "", "--output", "/dev/null",
            "--write-out", "%{http_connect} %{http_code}", "--header", "anthropic-version: 2023-06-01",
            "https://api.anthropic.com/v1/models"
        ]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let codes = String(decoding: bytes, as: UTF8.self).split(separator: " ").compactMap { Int($0) }
        guard codes.count == 2, codes[0] == 200, process.terminationStatus == 0 else {
            throw ProtectionError.proxyUnavailable(port, process.terminationStatus)
        }
        guard (200...299).contains(codes[1]) || codes[1] == 401 else {
            throw ProtectionError.unexpectedHTTP(codes[1])
        }
        return codes[1]
    }
}

enum ProtectionError: LocalizedError {
    case invalidPort
    case proxyUnavailable(Int, Int32)
    case unexpectedHTTP(Int)
    case unsupportedExitRegion(String)
    case exitGeoUnavailable
    case exitGeoSplit(String)
    case invalidSettings
    case unsupportedFile
    case cannotChange
    case existingBackup
    case invalidBackup
    case busy

    var errorDescription: String? {
        switch self {
        case .invalidPort: "请输入 1–65535 之间的 Clash Verge / 代理客户端端口。"
        case let .proxyUnavailable(port, code):
            "代理 127.0.0.1:\(port) 未能建立 Claude API 的 HTTPS 连接（curl \(code)）。"
        case .unexpectedHTTP(let code): "通过代理收到 HTTP \(code)，暂缓开启。"
        case .unsupportedExitRegion(let region):
            "当前出口位于 Anthropic 不支持的地区：\(region)。请切换至支持地区节点后再启动防护。"
        case .exitGeoUnavailable:
            "未能通过上游代理验证公网出口地区，暂缓启动防护。请确认节点网络畅通。"
        case .exitGeoSplit(let countries):
            "多源 GeoIP 检测到出口国家分流冲突（\(countries)），暂缓启动防护，请检查代理分流规则。"
        case .invalidSettings: "Claude Code 的用户配置或环境变量字段格式无效。"
        case .unsupportedFile: "设置文件或备份需要是普通文件。请检查是否使用了符号链接。"
        case .cannotChange: "写入期间发现配置被其他程序更新。请重试。"
        case .existingBackup: "已有一份待恢复的代理备份。请先关闭或恢复原有防护。"
        case .invalidBackup: "防护备份无法读取。原有文件已保留。"
        case .busy: "另一个窗口正在切换防护。请稍后重试。"
        }
    }
}

actor ClashProtection {
    enum Mode: String, Codable, Equatable, CaseIterable, Sendable {
        case guardProxy = "guard"
        case directClash = "direct"

        var title: String {
            switch self {
            case .guardProxy: "熔断守卫模式（推荐）"
            case .directClash: "仅写入代理端口"
            }
        }
    }

    enum Status: Equatable, Sendable {
        case off
        case active(port: Int, mode: Mode, upstreamPort: Int?, appliedEnv: [String: String])
        case recovery(port: Int, mode: Mode, upstreamPort: Int?, appliedEnv: [String: String])
    }

    fileprivate struct Backup: Codable, Sendable {
        let version: Int
        let path: String
        let port: Int
        let mode: Mode?
        let upstreamPort: Int?
        let appliedExtraEnv: [String: String]?
        let hadDirectory: Bool
        let hadFile: Bool
        let hadEnvironment: Bool
        let original: [String: String]

        var resolvedMode: Mode { mode ?? .directClash }
        var resolvedExtraEnv: [String: String] { appliedExtraEnv ?? [:] }
    }

    fileprivate struct FileContents {
        let bytes: Data
        let mode: mode_t

        static func read(_ url: URL) throws -> Self? {
            var attributes = stat()
            if lstat(url.path, &attributes) != 0 {
                if errno == ENOENT { return nil }
                throw posixError(errno)
            }
            guard (attributes.st_mode & S_IFMT) == S_IFREG else { throw ProtectionError.unsupportedFile }
            return try Self(bytes: Data(contentsOf: url), mode: attributes.st_mode & 0o777)
        }
    }

    fileprivate static let proxyKeys = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
    fileprivate static let allowedExtraKeys = Set(["TZ", "LANG", "LC_ALL"])
    fileprivate static let allManagedKeys = Set(proxyKeys).union(allowedExtraKeys)

    private let settings: URL
    private let backupFile: URL

    init(settings: URL? = nil, stateDirectory: URL? = nil) {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let custom = ProcessInfo.processInfo.environment["CLAUDE_CONFIG_DIR"]
        let config = custom.flatMap { $0.hasPrefix("/") ? URL(fileURLWithPath: $0, isDirectory: true) : nil }
        self.settings = settings ?? (config ?? home.appendingPathComponent(".claude", isDirectory: true))
            .appendingPathComponent("settings.json")
        let state = stateDirectory ?? home.appendingPathComponent(
            "Library/Application Support/local.claude-environment-check", isDirectory: true
        )
        backupFile = state.appendingPathComponent("clash-protection.json")
    }

    func status() throws -> Status {
        guard let backup = try Self.readBackup(at: backupFile) else { return .off }
        do {
            let file = try FileContents.read(URL(fileURLWithPath: backup.path))
            let object = try Self.readSettings(file)
            let env = try Self.readEnvironment(object)
            let proxy = Clash.proxyURL(backup.port)
            if Self.proxyKeys.allSatisfy({ (env[$0] as? String) == proxy }) {
                return .active(
                    port: backup.port,
                    mode: backup.resolvedMode,
                    upstreamPort: backup.upstreamPort,
                    appliedEnv: backup.resolvedExtraEnv
                )
            }
        } catch {
            return .recovery(
                port: backup.port,
                mode: backup.resolvedMode,
                upstreamPort: backup.upstreamPort,
                appliedEnv: backup.resolvedExtraEnv
            )
        }
        return .recovery(
            port: backup.port,
            mode: backup.resolvedMode,
            upstreamPort: backup.upstreamPort,
            appliedEnv: backup.resolvedExtraEnv
        )
    }

    func start(
        port: Int,
        mode: Mode = .directClash,
        upstreamPort: Int? = nil,
        extraEnv: [String: String] = [:]
    ) throws {
        guard (1...65535).contains(port) else { throw ProtectionError.invalidPort }
        let filteredExtra = extraEnv.filter { Self.allowedExtraKeys.contains($0.key) && !$0.value.isEmpty }
        let lock = try Self.operationLock(for: backupFile)
        defer { _ = close(lock) }
        guard try Self.readBackup(at: backupFile) == nil else { throw ProtectionError.existingBackup }
        let directory = settings.deletingLastPathComponent().resolvingSymlinksInPath()
        let target = directory.appendingPathComponent(settings.lastPathComponent)
        let file = try FileContents.read(target)
        var object = try Self.readSettings(file)
        var env = try Self.readEnvironment(object)
        var originals: [String: String] = [:]

        for key in Self.proxyKeys {
            if let value = env[key] {
                guard let string = value as? String else { throw ProtectionError.invalidSettings }
                originals[key] = string
            }
            env[key] = Clash.proxyURL(port)
        }
        for (key, newVal) in filteredExtra {
            if let value = env[key] {
                guard let string = value as? String else { throw ProtectionError.invalidSettings }
                originals[key] = string
            }
            env[key] = newVal
        }

        let manager = FileManager.default
        let backup = Backup(
            version: 3,
            path: target.path,
            port: port,
            mode: mode,
            upstreamPort: upstreamPort,
            appliedExtraEnv: filteredExtra.isEmpty ? nil : filteredExtra,
            hadDirectory: manager.fileExists(atPath: directory.path),
            hadFile: file != nil,
            hadEnvironment: object["env"] != nil,
            original: originals
        )
        object["env"] = env
        let updated = try Self.encodeSettings(object)

        try Self.write(try JSONEncoder().encode(backup), to: backupFile, replacing: nil, createOnly: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
        try Self.write(updated, to: target, replacing: file)
    }

    @discardableResult
    func stop() throws -> Int {
        try Self.performStop(backupFile: backupFile)
    }

    /// Synchronous, termination-safe restore for `NSApplicationDelegate.applicationWillTerminate`.
    /// Only restores if the active backup is in `.guardProxy` mode (whose local port is about to shut down).
    @discardableResult
    nonisolated static func restoreGuardModeOnTerminateSync(stateDirectory: URL? = nil) -> Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let state = stateDirectory ?? home.appendingPathComponent(
            "Library/Application Support/local.claude-environment-check", isDirectory: true
        )
        let backupFile = state.appendingPathComponent("clash-protection.json")
        guard let backup = try? readBackup(at: backupFile), backup.resolvedMode == .guardProxy else {
            return false
        }
        _ = try? performStop(backupFile: backupFile)
        return true
    }

    private static func performStop(backupFile: URL) throws -> Int {
        let lock = try operationLock(for: backupFile)
        defer { _ = close(lock) }
        guard let backup = try readBackup(at: backupFile) else { return 0 }
        let target = URL(fileURLWithPath: backup.path)
        var preserved = 0
        if let file = try FileContents.read(target) {
            var object = try readSettings(file)
            var env = try readEnvironment(object)
            var changed = false

            // Build complete map of keys -> values written by this tool
            var writtenMap: [String: String] = [:]
            let proxyVal = Clash.proxyURL(backup.port)
            for key in proxyKeys { writtenMap[key] = proxyVal }
            for (k, v) in backup.resolvedExtraEnv { writtenMap[k] = v }

            for (key, expectedWritten) in writtenMap {
                if (env[key] as? String) == expectedWritten {
                    if let original = backup.original[key] {
                        env[key] = original
                    } else {
                        env.removeValue(forKey: key)
                    }
                    changed = true
                } else if !matchesOriginal(env[key], backup.original[key]) {
                    preserved += 1
                }
            }

            if changed {
                if env.isEmpty && !backup.hadEnvironment {
                    object.removeValue(forKey: "env")
                } else {
                    object["env"] = env
                }
                if object.isEmpty && !backup.hadFile {
                    try confirmUnchanged(target, from: file)
                    try FileManager.default.removeItem(at: target)
                } else {
                    try write(try encodeSettings(object), to: target, replacing: file)
                }
            }
        }
        if !backup.hadDirectory {
            let directory = target.deletingLastPathComponent()
            if rmdir(directory.path) != 0 && ![ENOENT, ENOTEMPTY, EEXIST].contains(errno) {
                throw posixError(errno)
            }
        }
        try FileManager.default.removeItem(at: backupFile)
        return preserved
    }

    private static func operationLock(for backupFile: URL) throws -> Int32 {
        let state = backupFile.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let fd = open(state.appendingPathComponent("protection.lock").path,
                      O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { throw posixError(errno) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            let failure = errno
            _ = close(fd)
            if failure == EWOULDBLOCK { throw ProtectionError.busy }
            throw posixError(failure)
        }
        return fd
    }

    private static func matchesOriginal(_ current: Any?, _ original: String?) -> Bool {
        if let original { return current as? String == original }
        return current == nil
    }

    private static func readBackup(at backupFile: URL) throws -> Backup? {
        guard let file = try FileContents.read(backupFile) else { return nil }
        guard let backup = try? JSONDecoder().decode(Backup.self, from: file.bytes),
              (1...3).contains(backup.version),
              (1...65535).contains(backup.port),
              backup.path.hasPrefix("/"),
              URL(fileURLWithPath: backup.path).lastPathComponent == "settings.json",
              backup.original.keys.allSatisfy(allManagedKeys.contains),
              backup.resolvedExtraEnv.keys.allSatisfy(allowedExtraKeys.contains) else {
            throw ProtectionError.invalidBackup
        }
        return backup
    }

    private static func readSettings(_ file: FileContents?) throws -> [String: Any] {
        guard let file else { return [:] }
        guard let object = (try? JSONSerialization.jsonObject(with: file.bytes)) as? [String: Any] else {
            throw ProtectionError.invalidSettings
        }
        return object
    }

    private static func readEnvironment(_ object: [String: Any]) throws -> [String: Any] {
        guard let value = object["env"] else { return [:] }
        guard let env = value as? [String: Any] else { throw ProtectionError.invalidSettings }
        return env
    }

    private static func encodeSettings(_ object: [String: Any]) throws -> Data {
        var bytes = try JSONSerialization.data(withJSONObject: object,
                                               options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        bytes.append(0x0A)
        return bytes
    }

    private static func confirmUnchanged(_ url: URL, from expected: FileContents?) throws {
        let current = try FileContents.read(url)
        guard current?.bytes == expected?.bytes, current?.mode == expected?.mode else {
            throw ProtectionError.cannotChange
        }
    }

    private static func write(_ bytes: Data, to url: URL, replacing previous: FileContents?,
                              createOnly: Bool = false) throws {
        let template = url.deletingLastPathComponent()
            .appendingPathComponent(".environment-check.XXXXXXXX").path
        var path = template.utf8CString
        let fd = path.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard fd >= 0 else { throw posixError(errno) }
        let temporaryPath = String(decoding: path.dropLast().map { UInt8(bitPattern: $0) }, as: UTF8.self)
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer {
            try? handle.close()
            _ = unlink(temporaryPath)
        }
        try handle.write(contentsOf: bytes)
        guard fchmod(fd, previous?.mode ?? 0o600) == 0 else { throw posixError(errno) }
        try handle.synchronize()
        if createOnly {
            guard link(temporaryPath, url.path) == 0 else {
                if errno == EEXIST { throw ProtectionError.existingBackup }
                throw posixError(errno)
            }
        } else {
            try confirmUnchanged(url, from: previous)
            guard rename(temporaryPath, url.path) == 0 else { throw posixError(errno) }
        }
    }
}

private func posixError(_ value: Int32) -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: value) ?? .EIO)
}
