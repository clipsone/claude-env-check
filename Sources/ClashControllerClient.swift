import Darwin
import Foundation

struct ClashProxyGroupInfo: Identifiable, Equatable, Sendable {
    let name: String
    let type: String
    let current: String?
    let candidates: [String]

    var id: String { name }

    var isDynamicSwitching: Bool {
        let lower = type.lowercased()
        return lower == "urltest" || lower == "fallback" || lower == "loadbalance"
    }

    var isSelectable: Bool {
        type.lowercased() == "selector"
    }
}

struct ClashRouteResolution: Equatable, Sendable {
    let matchedRule: String
    let targetGroup: String
    let chain: [String]
    let leafNode: String
    let hasDynamicGroupInChain: Bool
    let dynamicGroups: [String]
    let isDirect: Bool
    let isRejected: Bool
    let selectorGroupForSwitching: ClashProxyGroupInfo?
}

struct ClashLiveConnection: Identifiable, Equatable, Sendable {
    let id: String
    let host: String
    let port: String
    let network: String
    let rule: String
    let rulePayload: String
    let chains: [String]
    let upload: Int64
    let download: Int64
    let start: String
    let isClaudeDomain: Bool

    var isDirect: Bool {
        chains.contains { $0.uppercased() == "DIRECT" }
    }

    var isRejected: Bool {
        chains.contains { $0.uppercased() == "REJECT" || $0.uppercased() == "REJECT-DROP" }
    }

    var isViolation: Bool {
        isClaudeDomain && isDirect
    }
}

struct ClashControllerSnapshot: Sendable {
    let endpoint: ClashControllerEndpoint
    let kernelVersion: String
    let isMeta: Bool
    let mode: String
    let tunEnabled: Bool
    let ipv6Enabled: Bool
    let mixedPort: Int?
    let claudeRoute: ClashRouteResolution?
    let totalConnections: Int
    let claudeConnections: [ClashLiveConnection]
    let directViolations: [ClashLiveConnection]
    let selectorGroups: [ClashProxyGroupInfo]
    let sampledAt: Date
}

enum ClashControllerError: LocalizedError {
    case connectionFailed(String)
    case httpError(Int, String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .connectionFailed(let msg): "无法连接 Clash 控制器：\(msg)"
        case let .httpError(code, msg): "Clash 控制器返回 HTTP \(code)\(msg.isEmpty ? "" : "：\(msg)")"
        case .invalidResponse: "Clash 控制器返回了无法解析的响应。"
        }
    }
}

/// Pure Swift HTTP/1.1 client for Clash / Mihomo External Controller supporting both Unix domain sockets and TCP.
/// Keeps controller secrets strictly in memory (never exposed via subprocess command lines).
enum ClashControllerClient {
    static func fetchSnapshot(endpoint: ClashControllerEndpoint) async throws -> ClashControllerSnapshot {
        try await Task.detached(priority: .userInitiated) {
            let versionJSON = try requestJSON(endpoint: endpoint, method: "GET", path: "/version")
            let configJSON = try requestJSON(endpoint: endpoint, method: "GET", path: "/configs")
            let proxiesJSON = try requestJSON(endpoint: endpoint, method: "GET", path: "/proxies")
            let rulesJSON = try? requestJSON(endpoint: endpoint, method: "GET", path: "/rules")
            let connJSON = try? requestJSON(endpoint: endpoint, method: "GET", path: "/connections")

            let version = (versionJSON["version"] as? String) ?? "unknown"
            let isMeta = (versionJSON["meta"] as? Bool) ?? version.lowercased().contains("meta")
            let mode = (configJSON["mode"] as? String) ?? "rule"
            let tunObj = configJSON["tun"] as? [String: Any]
            let tunEnabled = (tunObj?["enable"] as? Bool) ?? false
            let ipv6Enabled = (configJSON["ipv6"] as? Bool) ?? false
            let mixedPort = (configJSON["mixed-port"] as? Int).flatMap { $0 > 0 ? $0 : nil } ?? endpoint.mixedPort

            let proxiesMap = (proxiesJSON["proxies"] as? [String: Any]) ?? [:]
            var groupsByName: [String: ClashProxyGroupInfo] = [:]
            for (name, rawVal) in proxiesMap {
                guard let obj = rawVal as? [String: Any],
                      let type = obj["type"] as? String else { continue }
                let lower = type.lowercased()
                if ["selector", "urltest", "fallback", "loadbalance", "relay"].contains(lower) {
                    let info = ClashProxyGroupInfo(
                        name: name,
                        type: type,
                        current: obj["now"] as? String,
                        candidates: (obj["all"] as? [String]) ?? []
                    )
                    groupsByName[name] = info
                }
            }

            let rulesArray = (rulesJSON?["rules"] as? [[String: Any]]) ?? []
            let claudeRoute = resolveClaudeRoute(mode: mode, rules: rulesArray, groups: groupsByName)

            let rawConns = (connJSON?["connections"] as? [[String: Any]]) ?? []
            var claudeConns: [ClashLiveConnection] = []
            for item in rawConns {
                guard let id = item["id"] as? String,
                      let meta = item["metadata"] as? [String: Any] else { continue }
                let host = ((meta["host"] as? String)?.isEmpty == false ? meta["host"] as? String : nil)
                    ?? (meta["sniffHost"] as? String)
                    ?? (meta["destinationIP"] as? String)
                    ?? ""
                guard !host.isEmpty else { continue }
                let isClaude = ConnectionAuditLog.isClaudeHost(host)
                guard isClaude else { continue }
                let chains = (item["chains"] as? [String]) ?? []
                let conn = ClashLiveConnection(
                    id: id,
                    host: host,
                    port: String(describing: meta["destinationPort"] ?? ""),
                    network: (meta["network"] as? String) ?? "tcp",
                    rule: (item["rule"] as? String) ?? "",
                    rulePayload: (item["rulePayload"] as? String) ?? "",
                    chains: chains,
                    upload: (item["upload"] as? Int64) ?? Int64((item["upload"] as? Int) ?? 0),
                    download: (item["download"] as? Int64) ?? Int64((item["download"] as? Int) ?? 0),
                    start: (item["start"] as? String) ?? "",
                    isClaudeDomain: isClaude
                )
                claudeConns.append(conn)
            }

            let violations = claudeConns.filter(\.isViolation)
            let selectors = groupsByName.values
                .filter(\.isSelectable)
                .sorted { $0.name < $1.name }

            return ClashControllerSnapshot(
                endpoint: endpoint,
                kernelVersion: version,
                isMeta: isMeta,
                mode: mode,
                tunEnabled: tunEnabled,
                ipv6Enabled: ipv6Enabled,
                mixedPort: mixedPort,
                claudeRoute: claudeRoute,
                totalConnections: rawConns.count,
                claudeConnections: claudeConns,
                directViolations: violations,
                selectorGroups: selectors,
                sampledAt: Date()
            )
        }.value
    }

    static func closeConnection(endpoint: ClashControllerEndpoint, id: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
            let (status, body) = try rawRequest(endpoint: endpoint, method: "DELETE", path: "/connections/\(encoded)", body: nil)
            guard (200...299).contains(status) else {
                throw ClashControllerError.httpError(status, String(decoding: body, as: UTF8.self))
            }
        }.value
    }

    static func switchGroupNode(endpoint: ClashControllerEndpoint, group: String, node: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            let encoded = group.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? group
            let payload = try JSONSerialization.data(withJSONObject: ["name": node])
            let (status, body) = try rawRequest(endpoint: endpoint, method: "PUT", path: "/proxies/\(encoded)", body: payload)
            guard (200...299).contains(status) else {
                throw ClashControllerError.httpError(status, String(decoding: body, as: UTF8.self))
            }
        }.value
    }

    /// Ultra-lightweight (<2ms, zero internet traffic) local controller poll used by the 2-second node-change watcher
    /// to detect manual Clash node switches or mode changes before the 30-second external exit probe fires.
    static func fetchQuickRouteFingerprint(
        endpoint: ClashControllerEndpoint,
        ruleTargetGroup: String?
    ) async throws -> (mode: String, leafNode: String) {
        try await Task.detached(priority: .utility) {
            let configJSON = try requestJSON(endpoint: endpoint, method: "GET", path: "/configs")
            let proxiesJSON = try requestJSON(endpoint: endpoint, method: "GET", path: "/proxies")
            let mode = ((configJSON["mode"] as? String) ?? "rule").lowercased()
            if mode == "direct" {
                return (mode, "DIRECT")
            }

            let proxiesMap = (proxiesJSON["proxies"] as? [String: Any]) ?? [:]
            let startGroup: String
            if mode == "global" {
                startGroup = "GLOBAL"
            } else if let target = ruleTargetGroup, !target.isEmpty, proxiesMap[target] != nil {
                startGroup = target
            } else if proxiesMap["Claude-Pin"] != nil {
                startGroup = "Claude-Pin"
            } else {
                startGroup = "GLOBAL"
            }

            var cursor = startGroup
            var visited: Set<String> = [cursor]
            while let obj = proxiesMap[cursor] as? [String: Any],
                  let next = obj["now"] as? String,
                  !next.isEmpty,
                  visited.insert(next).inserted {
                cursor = next
            }
            return (mode, cursor)
        }.value
    }

    // MARK: - Route Resolution Analysis

    static func resolveClaudeRoute(
        mode: String,
        rules: [[String: Any]],
        groups: [String: ClashProxyGroupInfo]
    ) -> ClashRouteResolution? {
        let lowerMode = mode.lowercased()
        let matchedRule: String
        let target: String

        if lowerMode == "direct" {
            matchedRule = "全局直连模式 (mode: direct)"
            target = "DIRECT"
        } else if lowerMode == "global" {
            matchedRule = "全局代理模式 (mode: global)"
            target = "GLOBAL"
        } else {
            let probeHost = "api.anthropic.com"
            if let hit = findMatchingRule(for: probeHost, in: rules) {
                matchedRule = hit.ruleText
                target = hit.proxy
            } else {
                return nil
            }
        }

        // Walk the proxy group graph (guarding against cycles)
        var chain: [String] = [target]
        var visited: Set<String> = [target]
        var dynamicGroups: [String] = []
        var firstSelector: ClashProxyGroupInfo?
        var cursor = target

        while let group = groups[cursor] {
            if group.isDynamicSwitching {
                dynamicGroups.append("\(group.name) (\(group.type))")
            }
            if group.isSelectable && firstSelector == nil {
                firstSelector = group
            }
            guard let next = group.current, !next.isEmpty, visited.insert(next).inserted else {
                break
            }
            chain.append(next)
            cursor = next
        }

        let leaf = chain.last ?? target
        let upperLeaf = leaf.uppercased()
        return ClashRouteResolution(
            matchedRule: matchedRule,
            targetGroup: target,
            chain: chain,
            leafNode: leaf,
            hasDynamicGroupInChain: !dynamicGroups.isEmpty,
            dynamicGroups: dynamicGroups,
            isDirect: upperLeaf == "DIRECT",
            isRejected: upperLeaf == "REJECT" || upperLeaf == "REJECT-DROP",
            selectorGroupForSwitching: firstSelector
        )
    }

    private static func findMatchingRule(for host: String, in rules: [[String: Any]]) -> (ruleText: String, proxy: String)? {
        let lowerHost = host.lowercased()
        var matchFallback: (String, String)?

        for rule in rules {
            guard let type = (rule["type"] as? String)?.uppercased(),
                  let proxy = rule["proxy"] as? String else { continue }
            let payload = ((rule["payload"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let lowerPayload = payload.lowercased()

            switch type {
            case "DOMAIN":
                if lowerPayload == lowerHost {
                    return ("DOMAIN,\(payload)", proxy)
                }
            case "DOMAIN-SUFFIX":
                if lowerHost == lowerPayload || lowerHost.hasSuffix(".\(lowerPayload)") {
                    return ("DOMAIN-SUFFIX,\(payload)", proxy)
                }
            case "DOMAIN-KEYWORD":
                if !lowerPayload.isEmpty && lowerHost.contains(lowerPayload) {
                    return ("DOMAIN-KEYWORD,\(payload)", proxy)
                }
            case "GEOSITE":
                if lowerPayload.contains("anthropic") || lowerPayload.contains("claude") || lowerPayload == "geolocation-!cn" {
                    return ("GEOSITE,\(payload)", proxy)
                }
            case "RULE-SET":
                if lowerPayload.contains("claude") || lowerPayload.contains("anthropic") || lowerPayload.contains("ai") {
                    return ("RULE-SET,\(payload)", proxy)
                }
            case "MATCH":
                if matchFallback == nil {
                    matchFallback = ("MATCH", proxy)
                }
            default:
                break
            }
        }
        return matchFallback
    }

    // MARK: - Low-Level HTTP/1.1 Transport (Unix Socket + TCP)

    private static func requestJSON(endpoint: ClashControllerEndpoint, method: String, path: String) throws -> [String: Any] {
        let (status, body) = try rawRequest(endpoint: endpoint, method: method, path: path, body: nil)
        guard (200...299).contains(status) else {
            throw ClashControllerError.httpError(status, String(decoding: body, as: UTF8.self))
        }
        guard let obj = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else {
            throw ClashControllerError.invalidResponse
        }
        return obj
    }

    static func rawRequest(
        endpoint: ClashControllerEndpoint,
        method: String,
        path: String,
        body: Data?
    ) throws -> (Int, Data) {
        let fd: Int32
        let hostHeader: String
        switch endpoint.transport {
        case .unixSocket(let socketPath):
            fd = try connectUnixSocket(path: socketPath)
            hostHeader = "localhost"
        case let .tcp(host, port):
            fd = try connectTCPSocket(host: host, port: port)
            hostHeader = "\(host):\(port)"
        }
        defer { _ = close(fd) }

        var tv = timeval(tv_sec: 4, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var headers = "\(method) \(path) HTTP/1.1\r\n"
        headers += "Host: \(hostHeader)\r\n"
        headers += "Connection: close\r\n"
        if let secret = endpoint.secret, !secret.isEmpty {
            headers += "Authorization: Bearer \(secret)\r\n"
        }
        if let body {
            headers += "Content-Type: application/json\r\n"
            headers += "Content-Length: \(body.count)\r\n"
        }
        headers += "\r\n"

        var reqData = Data(headers.utf8)
        if let body { reqData.append(body) }

        try writeAll(fd: fd, data: reqData)
        let responseData = try readUntilEOF(fd: fd, maxBytes: 8 * 1024 * 1024)
        return try parseHTTPResponse(responseData)
    }

    private static func connectUnixSocket(path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw ClashControllerError.connectionFailed("无法创建 Unix Socket (errno \(errno))")
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let utf8 = Array(path.utf8)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path) - 1
        guard utf8.count <= maxLen else {
            _ = close(fd)
            throw ClashControllerError.connectionFailed("Unix Socket 路径过长")
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: maxLen + 1) { dst in
                for (i, b) in utf8.enumerated() { dst[i] = b }
                dst[utf8.count] = 0
            }
        }
        let res = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard res == 0 else {
            let err = errno
            _ = close(fd)
            throw ClashControllerError.connectionFailed("Unix Socket 连接失败 (errno \(err))")
        }
        return fd
    }

    private static func connectTCPSocket(host: String, port: Int) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw ClashControllerError.connectionFailed("无法创建 TCP Socket")
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        let resolvedHost = host == "localhost" ? "127.0.0.1" : host
        guard inet_pton(AF_INET, resolvedHost, &addr.sin_addr) == 1 else {
            _ = close(fd)
            throw ClashControllerError.connectionFailed("无效控制器地址：\(host)")
        }
        let res = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard res == 0 else {
            let err = errno
            _ = close(fd)
            throw ClashControllerError.connectionFailed("TCP 连接 \(host):\(port) 失败 (errno \(err))")
        }
        return fd
    }

    private static func writeAll(fd: Int32, data: Data) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { raw in
                send(fd, raw.baseAddress!.advanced(by: offset), data.count - offset, 0)
            }
            guard written > 0 else {
                throw ClashControllerError.connectionFailed("发送请求失败 (errno \(errno))")
            }
            offset += written
        }
    }

    private static func readUntilEOF(fd: Int32, maxBytes: Int) throws -> Data {
        var result = Data()
        var chunk = [UInt8](repeating: 0, count: 16384)
        while result.count < maxBytes {
            let n = chunk.withUnsafeMutableBytes { raw in
                recv(fd, raw.baseAddress!, raw.count, 0)
            }
            if n == 0 { break }
            if n < 0 {
                if errno == EINTR { continue }
                if !result.isEmpty { break }
                throw ClashControllerError.connectionFailed("读取响应失败 (errno \(errno))")
            }
            result.append(contentsOf: chunk.prefix(n))
        }
        return result
    }

    static func parseHTTPResponse(_ raw: Data) throws -> (Int, Data) {
        let delimiter = Data([0x0D, 0x0A, 0x0D, 0x0A])
        guard let range = raw.range(of: delimiter),
              let headerText = String(data: raw[..<range.lowerBound], encoding: .isoLatin1) else {
            throw ClashControllerError.invalidResponse
        }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else { throw ClashControllerError.invalidResponse }
        let statusParts = statusLine.split(separator: " ")
        guard statusParts.count >= 2, let code = Int(statusParts[1]) else {
            throw ClashControllerError.invalidResponse
        }

        var isChunked = false
        for line in lines.dropFirst() {
            if line.lowercased().hasPrefix("transfer-encoding:"), line.lowercased().contains("chunked") {
                isChunked = true
            }
        }

        let bodySlice = Data(raw[range.upperBound...])
        if isChunked {
            return (code, decodeChunked(bodySlice))
        }
        return (code, bodySlice)
    }

    static func decodeChunked(_ data: Data) -> Data {
        var output = Data()
        let crlf = Data([0x0D, 0x0A])
        var cursor = data.startIndex
        while cursor < data.endIndex {
            guard let lineEnd = data[cursor...].range(of: crlf) else { break }
            let sizeStr = String(decoding: data[cursor..<lineEnd.lowerBound], as: UTF8.self)
                .split(separator: ";").first?
                .trimmingCharacters(in: .whitespaces) ?? ""
            guard let chunkSize = Int(sizeStr, radix: 16), chunkSize >= 0 else { break }
            cursor = lineEnd.upperBound
            if chunkSize == 0 { break }
            let end = min(cursor + chunkSize, data.endIndex)
            output.append(data[cursor..<end])
            cursor = end
            if data[cursor...].starts(with: crlf) {
                cursor += 2
            }
        }
        return output
    }
}

// MARK: - 1-Click Clash Verge / Mihomo Anti-Leak Override Generator

enum OverrideFormat: String, CaseIterable, Identifiable, Sendable {
    case vergeJS = "Clash Verge 全局扩展脚本 (JS)"
    case clashYAML = "通用 Clash / Mihomo (YAML)"

    var id: Self { self }
}

enum ClashOverrideGenerator {
    static func generateVergeJavaScript(
        preferredNodeName: String? = nil,
        entryFunctionName: String = "main"
    ) -> String {
        let escapedPreferred: String = {
            guard let name = preferredNodeName?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !name.isEmpty,
                  name.uppercased() != "DIRECT",
                  name.uppercased() != "REJECT" else {
                return "null"
            }
            let safe = name
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
            return "\"\(safe)\""
        }()

        return """
// Clash Verge Rev 全局扩展脚本 — Claude 防风控 & 根治 DNS/ECS/QUIC/STUN 泄漏
// 支持通过「Claude 环境体检」一键写入与一键无损还原（订阅更新不会覆盖）

const CLAUDE_GROUP = "Claude-Pin";
const PREFERRED_NODE = \(escapedPreferred);
const CLAUDE_DOMAINS = [
  "anthropic.com",
  "claude.ai",
  "claude.com",
  "claudeusercontent.com",
  "challenges.cloudflare.com"
];
// 排除不支持地区节点，避免手误选到高风险地区
const UNSUPPORTED_NODE_RE = /香港|港|HK|Hong\\s*Kong|中国|大陆|回国|CN|澳门|MO|Macau|俄罗斯|俄|RU|Russia/i;

function \(entryFunctionName)(config) {
  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const safeNodes = proxies
    .map((p) => p && p.name)
    .filter((name) => typeof name === "string" && !UNSUPPORTED_NODE_RE.test(name));
  const fallbackNames = proxies.map((p) => p && p.name).filter(Boolean);
  let candidates = safeNodes.length > 0 ? safeNodes : fallbackNames;

  // 若当前正在使用的合规节点在候选列表中，自动置顶作为默认首选，免去重新手动选节点
  if (PREFERRED_NODE && candidates.includes(PREFERRED_NODE)) {
    candidates = [PREFERRED_NODE, ...candidates.filter((n) => n !== PREFERRED_NODE)];
  }

  // 1. 注入手动固定组 Claude-Pin（严禁 url-test/fallback 自动漂移）
  config["proxy-groups"] = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  config["proxy-groups"] = config["proxy-groups"].filter((g) => g && g.name !== CLAUDE_GROUP);
  config["proxy-groups"].unshift({
    name: CLAUDE_GROUP,
    type: "select",
    proxies: candidates.length > 0 ? candidates : ["DIRECT"]
  });

  // 2. 顶部前置规则：屏蔽 Claude QUIC + 屏蔽 WebRTC STUN + 强制 Claude 与探测域走固定组
  const prependRules = [
    ...CLAUDE_DOMAINS.map((d) => `AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,${d})),REJECT`),
    "AND,((NETWORK,UDP),(DST-PORT,3478)),REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,5349)),REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,19303)),REJECT",
    ...CLAUDE_DOMAINS.map((d) => `DOMAIN-SUFFIX,${d},${CLAUDE_GROUP}`),
    `DOMAIN-SUFFIX,ipwho.is,${CLAUDE_GROUP}`,
    `DOMAIN-SUFFIX,ipinfo.io,${CLAUDE_GROUP}`,
    `DOMAIN-SUFFIX,akahelp.net,${CLAUDE_GROUP}`,
    `DOMAIN,o-o.myaddr.l.google.com,${CLAUDE_GROUP}`
  ];
  config.rules = [...prependRules, ...(Array.isArray(config.rules) ? config.rules : [])];

  // 3. 根治国内 DNS / ECS 泄漏：
  //    - 节点自身域名 & 直连域名走国内 DoH（不卡顿）
  //    - 默认/海外/Claude/DNS 探测域名强制走代理远端 DoH（#Claude-Pin），彻底消除国内递归 DNS 与 ECS 暴露
  const remoteDoh = [
    `https://1.1.1.1/dns-query#${CLAUDE_GROUP}`,
    `https://8.8.8.8/dns-query#${CLAUDE_GROUP}`
  ];
  const cnDoh = [
    "https://223.5.5.5/dns-query",
    "https://doh.pub/dns-query"
  ];
  config.dns = Object.assign({}, config.dns, {
    enable: true,
    "respect-rules": true,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "proxy-server-nameserver": cnDoh,
    "direct-nameserver": cnDoh,
    "nameserver": remoteDoh,
    "nameserver-policy": Object.assign({}, config.dns && config.dns["nameserver-policy"], {
      "geosite:private": cnDoh,
      "geosite:cn": cnDoh,
      "+.anthropic.com": remoteDoh,
      "+.claude.ai": remoteDoh,
      "+.claude.com": remoteDoh,
      "+.claudeusercontent.com": remoteDoh,
      "+.akahelp.net": remoteDoh,
      "o-o.myaddr.l.google.com": remoteDoh
    })
  });

  return config;
}
"""
    }

    static func generateYAMLSnippet(groupName: String = "Claude-Pin") -> String {
        """
# 通用 Clash / Mihomo / FlClash / Stash 防泄漏规则片段
# 请确保已创建名为 \(groupName) 的手动选择组（type: select），切勿使用 url-test / fallback

dns:
  enable: true
  respect-rules: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver-policy:
    "+.anthropic.com": "https://1.1.1.1/dns-query#\(groupName)"
    "+.claude.ai": "https://1.1.1.1/dns-query#\(groupName)"
    "+.claude.com": "https://1.1.1.1/dns-query#\(groupName)"
    "+.claudeusercontent.com": "https://1.1.1.1/dns-query#\(groupName)"
    "+.akahelp.net": "https://1.1.1.1/dns-query#\(groupName)"
    "o-o.myaddr.l.google.com": "https://8.8.8.8/dns-query#\(groupName)"

rules:
  # 屏蔽 Claude 域名 QUIC (UDP/443)，防止绕过 TCP 代理审计
  - AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,anthropic.com)),REJECT
  - AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,claude.ai)),REJECT
  - AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,claude.com)),REJECT
  - AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,claudeusercontent.com)),REJECT
  - AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,challenges.cloudflare.com)),REJECT
  # 屏蔽 WebRTC STUN 端口，防止本地公网 IP 泄漏
  - AND,((NETWORK,UDP),(DST-PORT,3478)),REJECT
  - AND,((NETWORK,UDP),(DST-PORT,5349)),REJECT
  - AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT
  - AND,((NETWORK,UDP),(DST-PORT,19303)),REJECT
  # 强制 Claude 全家桶域名走手动固定组
  - DOMAIN-SUFFIX,anthropic.com,\(groupName)
  - DOMAIN-SUFFIX,claude.ai,\(groupName)
  - DOMAIN-SUFFIX,claude.com,\(groupName)
  - DOMAIN-SUFFIX,claudeusercontent.com,\(groupName)
  - DOMAIN-SUFFIX,challenges.cloudflare.com,\(groupName)
"""
    }
}
