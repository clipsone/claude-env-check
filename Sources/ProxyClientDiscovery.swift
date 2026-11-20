import Darwin
import Foundation

enum ProxyProtocolSupport: String, Codable, Equatable, Sendable {
    case mixed
    case httpOnly
    case socks5Only
    case none

    var label: String {
        switch self {
        case .mixed: "Mixed (HTTP + SOCKS5)"
        case .httpOnly: "HTTP"
        case .socks5Only: "SOCKS5"
        case .none: "未知"
        }
    }

    var supportsHTTP: Bool {
        self == .mixed || self == .httpOnly
    }
}

struct DiscoveredProxyClient: Identifiable, Equatable, Sendable {
    let clientName: String
    let processName: String
    let pid: Int
    let port: Int
    let protocols: ProxyProtocolSupport

    var id: String { "\(pid)-\(port)" }
}

enum ClashControllerTransport: Equatable, Sendable {
    case unixSocket(String)
    case tcp(host: String, port: Int)

    var displayLabel: String {
        switch self {
        case .unixSocket(let path):
            return "Unix Socket (\(URL(fileURLWithPath: path).lastPathComponent))"
        case let .tcp(host, port):
            return "HTTP \(host):\(port)"
        }
    }
}

struct ClashControllerEndpoint: Equatable, Sendable {
    let clientName: String
    let transport: ClashControllerTransport
    let secret: String?
    let mixedPort: Int?
    let configSource: String
}

enum ProxyClientDiscovery {
    private static let excludedPorts = Set((17899...17920)).union([39080, 39090, 39091])

    private static let knownClients: [(label: String, patterns: [String])] = [
        ("Clash Verge Rev", ["clash verge", "clash-verge", "verge-mihomo"]),
        ("FlClash", ["flclash"]),
        ("Mihomo Party", ["mihomo party", "mihomo-party", "sparkle"]),
        ("ClashX Pro", ["clashx pro", "clashxpro"]),
        ("ClashX Meta", ["clashx meta", "clashx.meta"]),
        ("ClashX", ["clashx"]),
        ("Surge", ["surge"]),
        ("Stash", ["stash"]),
        ("Hiddify", ["hiddify"]),
        ("Karing", ["karing"]),
        ("Sing-box", ["sing-box"]),
        ("V2Ray / Xray", ["v2ray", "xray", "nekoray"]),
        ("Mihomo", ["mihomo", "clash-meta", "clash"]),
    ]

    /// Scans local loopback listening TCP sockets belonging to known proxy clients,
    /// including root-owned Service Mode kernels (e.g. Clash Verge Rev verge-mihomo),
    /// independently probing HTTP CONNECT (200/407) and SOCKS5 so mixed-port proxies are accurately identified.
    static func scanRunningClients(home: URL = FileManager.default.homeDirectoryForCurrentUser) async -> [DiscoveredProxyClient] {
        await Task.detached(priority: .userInitiated) {
            let listeners = listLoopbackTCPListeners()
            let procMap = processCommandMap()

            var seenPorts: Set<Int> = []
            var results: [DiscoveredProxyClient] = []

            // 1. User-owned processes visible via lsof
            for row in listeners {
                guard !excludedPorts.contains(row.port), seenPorts.insert(row.port).inserted else {
                    continue
                }
                let fullCmd = procMap[row.pid] ?? row.command
                guard let label = matchClientLabel(command: fullCmd, fallback: row.command) else {
                    continue
                }
                let proto = probePortProtocols(port: row.port)
                guard proto != .none else { continue }
                let procName = URL(fileURLWithPath: fullCmd).lastPathComponent
                results.append(DiscoveredProxyClient(
                    clientName: label,
                    processName: procName.isEmpty ? row.command : procName,
                    pid: row.pid,
                    port: row.port,
                    protocols: proto
                ))
            }

            // 2. Root-owned service-mode kernels (invisible to unprivileged lsof, visible in `ps`)
            let runningKernels: [(pid: Int, label: String, procName: String)] = procMap.compactMap { (pid, cmd) in
                guard let label = matchClientLabel(command: cmd, fallback: cmd) else { return nil }
                let procName = URL(fileURLWithPath: cmd).lastPathComponent
                return (pid, label, procName)
            }
            if !runningKernels.isEmpty {
                var candidatePorts: [(port: Int, preferredLabel: String)] = []
                if let vergePort = Clash.detectedPort(home: home) {
                    candidatePorts.append((vergePort, "Clash Verge Rev"))
                }
                // Check config-declared ports across known client configs
                let extraConfigs: [(String, URL, [String])] = [
                    ("Clash Verge Rev", home.appendingPathComponent("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"), ["clash-verge.yaml", "config.yaml"]),
                    ("Mihomo Party", home.appendingPathComponent("Library/Application Support/mihomo-party"), ["work/config.yaml", "config.yaml"]),
                    ("FlClash", home.appendingPathComponent("Library/Application Support/com.follow.clash"), ["config.yaml"]),
                    ("ClashX Meta", home.appendingPathComponent(".config/clash.meta"), ["config.yaml"]),
                    ("ClashX", home.appendingPathComponent(".config/clash"), ["config.yaml"]),
                    ("Stash", home.appendingPathComponent("Library/Application Support/Stash"), ["config.yaml"]),
                ]
                for (clientLabel, dir, files) in extraConfigs {
                    for f in files {
                        guard let text = try? String(contentsOf: dir.appendingPathComponent(f), encoding: .utf8) else { continue }
                        let parsed = parseSimpleTopLevelYAML(text)
                        for key in ["mixed-port", "port", "socks-port"] {
                            if let p = parsed[key].flatMap(Clash.validPort) {
                                candidatePorts.append((p, clientLabel))
                            }
                        }
                    }
                }
                // Common default ports when matching client is actively running
                if runningKernels.contains(where: { $0.label == "Surge" }) {
                    candidatePorts.append((6152, "Surge"))
                    candidatePorts.append((6153, "Surge"))
                }
                if runningKernels.contains(where: { $0.label.contains("Clash") || $0.label.contains("Mihomo") }) {
                    candidatePorts.append((7897, "Clash Verge Rev"))
                    candidatePorts.append((7890, "Mihomo"))
                }

                for (port, preferredLabel) in candidatePorts {
                    guard !excludedPorts.contains(port), !seenPorts.contains(port) else { continue }
                    let proto = probePortProtocols(port: port)
                    guard proto != .none else { continue }
                    seenPorts.insert(port)
                    let matchedKernel = runningKernels.first {
                        $0.label == preferredLabel || $0.procName.lowercased().contains("mihomo")
                    } ?? runningKernels.first!
                    results.append(DiscoveredProxyClient(
                        clientName: preferredLabel,
                        processName: matchedKernel.procName,
                        pid: matchedKernel.pid,
                        port: port,
                        protocols: proto
                    ))
                }
            }

            return results.sorted { lhs, rhs in
                if lhs.protocols.supportsHTTP != rhs.protocols.supportsHTTP {
                    return lhs.protocols.supportsHTTP
                }
                return lhs.port < rhs.port
            }
        }.value
    }

    /// Auto-discovers running Clash / Mihomo External Controller endpoints (live process flags, Service Mode Unix socket, or config YAML) and secret.
    static func discoverControllers(home: URL = FileManager.default.homeDirectoryForCurrentUser) async -> [ClashControllerEndpoint] {
        await Task.detached(priority: .userInitiated) {
            let candidates: [(client: String, dir: URL, files: [String])] = [
                ("Clash Verge Rev",
                 home.appendingPathComponent("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"),
                 ["clash-verge.yaml", "config.yaml", "verge.yaml"]),
                ("Mihomo Party",
                 home.appendingPathComponent("Library/Application Support/mihomo-party"),
                 ["work/config.yaml", "config.yaml"]),
                ("Sparkle",
                 home.appendingPathComponent("Library/Application Support/sparkle"),
                 ["work/config.yaml", "config.yaml"]),
                ("FlClash",
                 home.appendingPathComponent("Library/Application Support/com.follow.clash"),
                 ["config.yaml"]),
                ("ClashX Meta",
                 home.appendingPathComponent(".config/clash.meta"),
                 ["config.yaml"]),
                ("ClashX",
                 home.appendingPathComponent(".config/clash"),
                 ["config.yaml"]),
                ("Stash",
                 home.appendingPathComponent("Library/Application Support/Stash"),
                 ["config.yaml"]),
            ]

            var endpoints: [ClashControllerEndpoint] = []
            var seenTransports: [ClashControllerTransport] = []
            let fm = FileManager.default

            // Read secrets/mixedPorts from configs first so live process sockets inherit their auth secret
            var secretsByClient: [String: String] = [:]
            var mixedPortsByClient: [String: Int] = [:]
            var parsedConfigs: [(client: String, unixPath: String?, tcpAddress: String?, secret: String?, mixedPort: Int?, source: String)] = []

            for entry in candidates {
                var unixPath: String?
                var tcpAddress: String?
                var secret: String?
                var mixedPort: Int?
                var matchedFile: String?

                for rel in entry.files {
                    let fileURL = entry.dir.appendingPathComponent(rel)
                    guard let text = try? String(contentsOf: fileURL, encoding: .utf8) else { continue }
                    if matchedFile == nil { matchedFile = fileURL.path }
                    let parsed = parseSimpleTopLevelYAML(text)
                    if unixPath == nil, let u = parsed["external-controller-unix"], !u.isEmpty {
                        unixPath = u
                    }
                    if tcpAddress == nil, let t = parsed["external-controller"], !t.isEmpty {
                        tcpAddress = t
                    }
                    if secret == nil, let s = parsed["secret"], !s.isEmpty {
                        secret = s
                    }
                    if mixedPort == nil {
                        if let m = parsed["mixed-port"].flatMap(Clash.validPort) {
                            mixedPort = m
                        } else if let m = parsed["verge_mixed_port"].flatMap(Clash.validPort) {
                            mixedPort = m
                        } else if let m = parsed["port"].flatMap(Clash.validPort) {
                            mixedPort = m
                        }
                    }
                }
                if let secret { secretsByClient[entry.client] = secret }
                if let mixedPort { mixedPortsByClient[entry.client] = mixedPort }
                parsedConfigs.append((entry.client, unixPath, tcpAddress, secret, mixedPort, matchedFile ?? entry.dir.path))
            }

            // Priority 1: Live running mihomo/clash process command-line flags (-ext-ctl-unix / -ext-ctl)
            for live in discoverLiveProcessControllers() {
                if !seenTransports.contains(live.transport) {
                    seenTransports.append(live.transport)
                    let secret = secretsByClient[live.clientName] ?? secretsByClient["Clash Verge Rev"]
                    let mp = mixedPortsByClient[live.clientName] ?? Clash.detectedPort(home: home)
                    endpoints.append(ClashControllerEndpoint(
                        clientName: live.clientName,
                        transport: live.transport,
                        secret: secret,
                        mixedPort: mp,
                        configSource: live.source
                    ))
                }
            }

            // Priority 2: Known macOS Clash Verge Rev Service Mode socket path
            let uid = getuid()
            let serviceSockets = [
                "/var/run/clash-verge-service/users/\(uid)/verge-mihomo.sock",
                URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("verge-mihomo.sock").path,
                "/tmp/verge/verge-mihomo.sock",
            ]
            for sock in serviceSockets where fm.fileExists(atPath: sock) {
                let transport = ClashControllerTransport.unixSocket(sock)
                if !seenTransports.contains(transport) {
                    seenTransports.append(transport)
                    endpoints.append(ClashControllerEndpoint(
                        clientName: "Clash Verge Rev",
                        transport: transport,
                        secret: secretsByClient["Clash Verge Rev"],
                        mixedPort: mixedPortsByClient["Clash Verge Rev"] ?? Clash.detectedPort(home: home),
                        configSource: sock
                    ))
                }
            }

            // Priority 3: Static config file Unix sockets and TCP addresses
            for cfg in parsedConfigs {
                if let unixPath = cfg.unixPath, fm.fileExists(atPath: unixPath) {
                    let transport = ClashControllerTransport.unixSocket(unixPath)
                    if !seenTransports.contains(transport) {
                        seenTransports.append(transport)
                        endpoints.append(ClashControllerEndpoint(
                            clientName: cfg.client,
                            transport: transport,
                            secret: cfg.secret,
                            mixedPort: cfg.mixedPort,
                            configSource: cfg.source
                        ))
                    }
                }
                if let tcpAddress = cfg.tcpAddress, let (host, port) = parseControllerHostPort(tcpAddress) {
                    let transport = ClashControllerTransport.tcp(host: host, port: port)
                    if !seenTransports.contains(transport) {
                        seenTransports.append(transport)
                        endpoints.append(ClashControllerEndpoint(
                            clientName: cfg.client,
                            transport: transport,
                            secret: cfg.secret,
                            mixedPort: cfg.mixedPort,
                            configSource: cfg.source
                        ))
                    }
                }
            }

            return endpoints
        }.value
    }

    private static func discoverLiveProcessControllers() -> [(clientName: String, transport: ClashControllerTransport, source: String)] {
        guard let output = runCommand("/bin/ps", ["-axo", "pid=,args="]) else { return [] }
        let fm = FileManager.default
        var found: [(String, ClashControllerTransport, String)] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let text = String(line)
            let lower = text.lowercased()
            guard lower.contains("mihomo") || lower.contains("clash") else { continue }
            let clientLabel = matchClientLabel(command: text, fallback: text) ?? "Mihomo"
            if let range = text.range(of: "-ext-ctl-unix ") {
                let rest = text[range.upperBound...].trimmingCharacters(in: .whitespaces)
                // Stop before next CLI flag (" -") if any
                let sockPath: String
                if let nextFlag = rest.range(of: " -") {
                    sockPath = String(rest[..<nextFlag.lowerBound]).trimmingCharacters(in: .whitespaces)
                } else {
                    sockPath = rest
                }
                if !sockPath.isEmpty, fm.fileExists(atPath: sockPath) {
                    found.append((clientLabel, .unixSocket(sockPath), "运行中进程 -ext-ctl-unix"))
                }
            }
            if let range = text.range(of: "-ext-ctl ") {
                let rest = text[range.upperBound...].trimmingCharacters(in: .whitespaces)
                let token = rest.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
                if let (host, port) = parseControllerHostPort(token) {
                    found.append((clientLabel, .tcp(host: host, port: port), "运行中进程 -ext-ctl"))
                }
            }
        }
        return found
    }

    // MARK: - YAML & Parsing Helpers

    static func parseSimpleTopLevelYAML(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for rawLine in text.split(whereSeparator: \.isNewline) {
            // Only parse top-level keys (no leading indentation)
            guard let first = rawLine.first, !first.isWhitespace, first != "#" else { continue }
            guard let colon = rawLine.firstIndex(of: ":") else { continue }
            let key = String(rawLine[..<colon]).trimmingCharacters(in: .whitespaces)
            var valuePart = String(rawLine[rawLine.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if valuePart.hasPrefix("'") || valuePart.hasPrefix("\"") {
                let quote = valuePart.first!
                if let endQuote = valuePart.dropFirst().firstIndex(of: quote) {
                    valuePart = String(valuePart[valuePart.index(after: valuePart.startIndex)..<endQuote])
                } else {
                    valuePart = valuePart.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                }
            } else {
                if let commentIdx = valuePart.firstIndex(of: "#") {
                    valuePart = String(valuePart[..<commentIdx]).trimmingCharacters(in: .whitespaces)
                }
            }
            if !key.isEmpty && !valuePart.isEmpty && valuePart != "null" && valuePart != "~" {
                result[key] = valuePart
            }
        }
        return result
    }

    static func parseControllerHostPort(_ raw: String) -> (String, Int)? {
        let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "https://", with: "")
        guard !cleaned.isEmpty else { return nil }
        if cleaned.hasPrefix(":"), let port = Clash.validPort(String(cleaned.dropFirst())) {
            return ("127.0.0.1", port)
        }
        if let colon = cleaned.lastIndex(of: ":"),
           let port = Clash.validPort(String(cleaned[cleaned.index(after: colon)...])) {
            var host = String(cleaned[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
            if host.isEmpty || host == "0.0.0.0" || host == "::" || host == "*" {
                host = "127.0.0.1"
            }
            return (host, port)
        }
        return nil
    }

    static func matchClientLabel(command: String, fallback: String) -> String? {
        let combined = "\(command) \(fallback)".lowercased()
        for entry in knownClients {
            if entry.patterns.contains(where: { combined.contains($0) }) {
                return entry.label
            }
        }
        return nil
    }

    // MARK: - Process & Socket Inspection

    private struct ListenerRow {
        let command: String
        let pid: Int
        let port: Int
    }

    private static func listLoopbackTCPListeners() -> [ListenerRow] {
        guard let output = runCommand("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"]) else {
            return []
        }
        var rows: [ListenerRow] = []
        for line in output.split(whereSeparator: \.isNewline).dropFirst() {
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 9, let pid = Int(parts[1]) else { continue }
            let cmd = String(parts[0])
            // Address token looks like "127.0.0.1:7897", "*:7897", "[::1]:7897"
            let nameIdx = parts.count >= 10 && parts.last == "(LISTEN)" ? parts.count - 2 : parts.count - 1
            let endpoint = String(parts[nameIdx])
            guard endpoint.hasPrefix("127.0.0.1:") || endpoint.hasPrefix("*:") || endpoint.hasPrefix("[::1]:") || endpoint.hasPrefix("[::]:") else {
                continue
            }
            guard let colon = endpoint.lastIndex(of: ":"),
                  let port = Clash.validPort(String(endpoint[endpoint.index(after: colon)...])) else {
                continue
            }
            rows.append(ListenerRow(command: cmd, pid: pid, port: port))
        }
        return rows
    }

    private static func processCommandMap() -> [Int: String] {
        guard let output = runCommand("/bin/ps", ["-axo", "pid=,comm="]) else { return [:] }
        var map: [Int: String] = [:]
        for line in output.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let space = trimmed.firstIndex(where: \.isWhitespace),
                  let pid = Int(trimmed[..<space]) else { continue }
            let comm = trimmed[space...].trimmingCharacters(in: .whitespaces)
            if !comm.isEmpty { map[pid] = comm }
        }
        return map
    }

    private static func runCommand(_ path: String, _ args: [String]) -> String? {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Independent HTTP + SOCKS5 Protocol Probing (Fixes Mixed-Port Blindness)

    static func probePortProtocols(port: Int) -> ProxyProtocolSupport {
        let http = probeHTTPProxy(port: port)
        let socks = probeSOCKS5Proxy(port: port)
        switch (http, socks) {
        case (true, true): return .mixed
        case (true, false): return .httpOnly
        case (false, true): return .socks5Only
        case (false, false): return .none
        }
    }

    private static func probeSOCKS5Proxy(port: Int) -> Bool {
        guard let fd = connectLoopbackTCP(port: port, timeoutMs: 300) else { return false }
        defer { _ = close(fd) }
        var greeting: [UInt8] = [0x05, 0x01, 0x00]
        guard writeAll(fd: fd, bytes: &greeting, count: greeting.count, timeoutMs: 250) else { return false }
        var reply = [UInt8](repeating: 0, count: 2)
        guard readExact(fd: fd, buffer: &reply, count: 2, timeoutMs: 300) else { return false }
        return reply[0] == 0x05 && reply[1] != 0xFF
    }

    private static func probeHTTPProxy(port: Int) -> Bool {
        guard let fd = connectLoopbackTCP(port: port, timeoutMs: 300) else { return false }
        defer { _ = close(fd) }
        var req = Array("CONNECT www.gstatic.com:443 HTTP/1.1\r\nHost: www.gstatic.com:443\r\n\r\n".utf8)
        guard writeAll(fd: fd, bytes: &req, count: req.count, timeoutMs: 250) else { return false }
        var buf = [UInt8](repeating: 0, count: 64)
        let n = readSome(fd: fd, buffer: &buf, maxCount: buf.count, timeoutMs: 800)
        guard n >= 12 else { return false }
        let line = String(decoding: buf.prefix(n), as: UTF8.self).components(separatedBy: "\r\n").first ?? ""
        let parts = line.split(separator: " ")
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/1.") else { return false }
        // Only accept 200 (tunnel established) or 407 (proxy auth required) — reject 400/404/405 web servers!
        return parts[1] == "200" || parts[1] == "407"
    }

    private static func connectLoopbackTCP(port: Int, timeoutMs: Int32) -> Int32? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
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
        if res == 0 { return fd }
        guard errno == EINPROGRESS else {
            _ = close(fd)
            return nil
        }
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, timeoutMs) > 0 else {
            _ = close(fd)
            return nil
        }
        var soErr: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &len) == 0, soErr == 0 else {
            _ = close(fd)
            return nil
        }
        return fd
    }

    private static func writeAll(fd: Int32, bytes: inout [UInt8], count: Int, timeoutMs: Int32) -> Bool {
        var sent = 0
        while sent < count {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&pfd, 1, timeoutMs) > 0 else { return false }
            let n = bytes.withUnsafeBytes { raw in
                send(fd, raw.baseAddress!.advanced(by: sent), count - sent, 0)
            }
            if n <= 0 { return false }
            sent += n
        }
        return true
    }

    private static func readExact(fd: Int32, buffer: inout [UInt8], count: Int, timeoutMs: Int32) -> Bool {
        var got = 0
        while got < count {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&pfd, 1, timeoutMs) > 0 else { return false }
            let n = buffer.withUnsafeMutableBytes { raw in
                recv(fd, raw.baseAddress!.advanced(by: got), count - got, 0)
            }
            if n <= 0 { return false }
            got += n
        }
        return true
    }

    private static func readSome(fd: Int32, buffer: inout [UInt8], maxCount: Int, timeoutMs: Int32) -> Int {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, timeoutMs) > 0 else { return 0 }
        let n = buffer.withUnsafeMutableBytes { raw in
            recv(fd, raw.baseAddress!, maxCount, 0)
        }
        return max(0, n)
    }
}
