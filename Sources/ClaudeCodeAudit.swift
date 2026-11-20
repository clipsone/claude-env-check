import AppKit
import Darwin
import Foundation

struct ClaudeCodeAuditReport: Sendable {
    struct ShellOverride: Equatable, Sendable {
        let file: String
        let line: Int
        let key: String
    }

    let cliPath: String?
    let cliVersion: String?
    let configDirectory: String
    let settingsExists: Bool
    let settingsParseError: Bool
    let configuredProxies: [String: String]
    let deadLocalPorts: [Int]
    let proxyMismatch: Bool
    let dangerousNoProxy: [String]
    let customBaseURLPresent: Bool
    let processTZ: String?
    let processLang: String?
    let localSettingsOverrides: [String]
    let shellOverrides: [ShellOverride]
    let processEnvOverrides: [String]
    let desktopVersion: String?
    let desktopFound: Bool
    let desktopRunning: Bool
}

enum ClaudeCodeAudit {
    private static let proxyKeys = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"]
    private static let auditedEnvKeys = Set(proxyKeys + ["NO_PROXY", "no_proxy", "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR"])

    @MainActor
    static func inspect() async -> ClaudeCodeAuditReport {
        let desktop = inspectDesktop()
        return await Task.detached(priority: .userInitiated) {
            let home = FileManager.default.homeDirectoryForCurrentUser
            let env = ProcessInfo.processInfo.environment
            let customDir = env["CLAUDE_CONFIG_DIR"].flatMap { $0.hasPrefix("/") ? $0 : nil }
            let configDir = customDir ?? home.appendingPathComponent(".claude").path

            let (cliPath, cliVersion) = locateClaudeCLI(home: home, env: env)
            let settingsAudit = inspectSettingsJSON(at: URL(fileURLWithPath: configDir).appendingPathComponent("settings.json"))
            let localOverrides = inspectLocalSettingsOverrides(
                at: URL(fileURLWithPath: configDir).appendingPathComponent("settings.local.json")
            )
            let shellOverrides = scanShellRCFiles(home: home)
            let procOverrides = auditedEnvKeys.filter { key in
                guard let val = env[key]?.trimmingCharacters(in: .whitespacesAndNewlines) else { return false }
                return !val.isEmpty
            }.sorted()

            return ClaudeCodeAuditReport(
                cliPath: cliPath,
                cliVersion: cliVersion,
                configDirectory: configDir,
                settingsExists: settingsAudit.exists,
                settingsParseError: settingsAudit.parseError,
                configuredProxies: settingsAudit.proxies,
                deadLocalPorts: settingsAudit.deadLocalPorts,
                proxyMismatch: settingsAudit.proxyMismatch,
                dangerousNoProxy: settingsAudit.dangerousNoProxy,
                customBaseURLPresent: settingsAudit.customBaseURLPresent,
                processTZ: settingsAudit.processTZ,
                processLang: settingsAudit.processLang,
                localSettingsOverrides: localOverrides,
                shellOverrides: shellOverrides,
                processEnvOverrides: procOverrides,
                desktopVersion: desktop.version,
                desktopFound: desktop.found,
                desktopRunning: desktop.running
            )
        }.value
    }

    @MainActor
    private static func inspectDesktop() -> (found: Bool, version: String?, running: Bool) {
        let bundleID = "com.anthropic.claudefordesktop"
        let running = !NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else {
            return (false, nil, running)
        }
        let version = Bundle(url: url)?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        return (true, version?.isEmpty == false ? version : nil, running)
    }

    private static func locateClaudeCLI(home: URL, env: [String: String]) -> (path: String?, version: String?) {
        var candidates: [String] = [
            "/opt/homebrew/bin/claude",
            "/usr/local/bin/claude",
            home.appendingPathComponent(".local/bin/claude").path,
            home.appendingPathComponent(".npm-global/bin/claude").path,
            home.appendingPathComponent(".volta/bin/claude").path,
            home.appendingPathComponent(".bun/bin/claude").path,
        ]
        if let pathEnv = env["PATH"] {
            for dir in pathEnv.split(separator: ":") {
                let candidate = URL(fileURLWithPath: String(dir)).appendingPathComponent("claude").path
                if !candidates.contains(candidate) {
                    candidates.append(candidate)
                }
            }
        }
        let fm = FileManager.default
        guard let executable = candidates.first(where: { fm.isExecutableFile(atPath: $0) }) else {
            return (nil, nil)
        }
        let version = readCLIVersion(executable)
        return (executable, version)
    }

    private static func readCLIVersion(_ path: String) -> String? {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--version"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return nil
        }

        let deadline = Date().addingTimeInterval(2.5)
        while process.isRunning && Date() < deadline {
            usleep(20_000)
        }
        if process.isRunning {
            process.terminate()
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0,
              let text = String(data: data, encoding: .utf8)?
                .split(whereSeparator: \.isNewline).first
                .map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
              !text.isEmpty else {
            return nil
        }
        return text
    }

    private struct SettingsAudit {
        var exists = false
        var parseError = false
        var proxies: [String: String] = [:]
        var deadLocalPorts: [Int] = []
        var proxyMismatch = false
        var dangerousNoProxy: [String] = []
        var customBaseURLPresent = false
        var processTZ: String?
        var processLang: String?
    }

    private static func inspectSettingsJSON(at url: URL) -> SettingsAudit {
        var result = SettingsAudit()
        guard FileManager.default.fileExists(atPath: url.path) else { return result }
        result.exists = true
        guard let data = try? Data(contentsOf: url),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            result.parseError = true
            return result
        }
        guard let env = root["env"] as? [String: Any] else { return result }

        for key in proxyKeys {
            if let value = env[key] as? String {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    result.proxies[key] = trimmed
                }
            }
        }

        if let tz = env["TZ"] as? String, !tz.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            result.processTZ = tz.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if let lang = (env["LANG"] as? String) ?? (env["LC_ALL"] as? String),
           !lang.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            result.processLang = lang.trimmingCharacters(in: .whitespacesAndNewlines)
        }

        if let base = env["ANTHROPIC_BASE_URL"] as? String,
           !base.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            result.customBaseURLPresent = true
        }

        // Check consistency across configured HTTP/HTTPS proxy keys
        let uniqueValues = Set(result.proxies.values)
        if uniqueValues.count > 1 {
            result.proxyMismatch = true
        }

        // Check whether localhost proxy ports are actually listening
        var checkedPorts: Set<Int> = []
        var deadPorts: [Int] = []
        for value in uniqueValues {
            if let port = extractLocalhostPort(from: value), checkedPorts.insert(port).inserted {
                if !isLocalPortReachable(port: port) {
                    deadPorts.append(port)
                }
            }
        }
        result.deadLocalPorts = deadPorts.sorted()

        // Check NO_PROXY / no_proxy for dangerous Claude bypasses
        var riskyBypass: [String] = []
        for key in ["NO_PROXY", "no_proxy"] {
            guard let raw = env[key] as? String else { continue }
            for entry in raw.split(separator: ",") {
                let token = entry.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if isDangerousNoProxyToken(token), !riskyBypass.contains(token) {
                    riskyBypass.append(token)
                }
            }
        }
        result.dangerousNoProxy = riskyBypass
        return result
    }

    private static func inspectLocalSettingsOverrides(at url: URL) -> [String] {
        guard let data = try? Data(contentsOf: url),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let env = root["env"] as? [String: Any] else {
            return []
        }
        return env.keys.filter { key in
            auditedEnvKeys.contains(key) &&
            (env[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
        }.sorted()
    }

    private static func scanShellRCFiles(home: URL) -> [ClaudeCodeAuditReport.ShellOverride] {
        let rcFiles = [".zshrc", ".zprofile", ".bashrc", ".bash_profile"]
        var findings: [ClaudeCodeAuditReport.ShellOverride] = []
        for name in rcFiles {
            let url = home.appendingPathComponent(name)
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let lines = text.components(separatedBy: .newlines)
            for (idx, rawLine) in lines.enumerated() {
                let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                let body = trimmed.hasPrefix("export ")
                    ? String(trimmed.dropFirst(7)).trimmingCharacters(in: .whitespaces)
                    : trimmed
                guard let eq = body.firstIndex(of: "=") else { continue }
                let key = String(body[..<eq]).trimmingCharacters(in: .whitespaces)
                if auditedEnvKeys.contains(key) {
                    findings.append(.init(file: "~\(name.hasPrefix("/") ? name : "/\(name)")", line: idx + 1, key: key))
                }
            }
        }
        return findings
    }

    static func isDangerousNoProxyToken(_ token: String) -> Bool {
        let clean = token.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if clean == "*" { return true }
        let stripped = clean.hasPrefix(".") ? String(clean.dropFirst()) : clean
        return stripped == "anthropic.com"
            || stripped.hasSuffix(".anthropic.com")
            || stripped == "claude.ai"
            || stripped.hasSuffix(".claude.ai")
            || stripped == "claude.com"
            || stripped.hasSuffix(".claude.com")
    }

    static func extractLocalhostPort(from proxyString: String) -> Int? {
        let candidate = proxyString.contains("://") ? proxyString : "http://\(proxyString)"
        guard let url = URL(string: candidate),
              let host = url.host?.lowercased(),
              ["127.0.0.1", "localhost", "::1"].contains(host),
              let port = url.port, (1...65535).contains(port) else {
            return nil
        }
        return port
    }

    private static func isLocalPortReachable(port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { _ = close(fd) }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        _ = inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)

        let res = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if res == 0 { return true }
        guard errno == EINPROGRESS else { return false }

        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, 300) > 0 else { return false }

        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 else { return false }
        return soError == 0
    }
}
