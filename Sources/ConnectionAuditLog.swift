import Darwin
import Foundation

enum ConnectionDecision: String, Codable, Equatable, CaseIterable, Sendable {
    case allowed
    case blocked
    case upstreamError
    case rejectedLoopback

    var label: String {
        switch self {
        case .allowed: "已放行"
        case .blocked: "已熔断"
        case .upstreamError: "上游失败"
        case .rejectedLoopback: "拒绝回环"
        }
    }
}

struct ConnectionAuditEntry: Codable, Equatable, Identifiable, Sendable {
    let id: UUID
    let startedAt: Date
    let endedAt: Date?
    let method: String
    let host: String
    let port: Int
    let isClaudeDomain: Bool
    let decision: ConnectionDecision
    let reason: String?
    let exitIP: String?
    let exitCountry: String?
    let bytesUp: Int64
    let bytesDown: Int64
    let durationMs: Int?
}

struct ConnectionAuditStats: Equatable, Sendable {
    let total: Int
    let allowed: Int
    let blocked: Int
    let upstreamErrors: Int
    let claudeTotal: Int

    static let empty = ConnectionAuditStats(total: 0, allowed: 0, blocked: 0, upstreamErrors: 0, claudeTotal: 0)
}

actor ConnectionAuditLog {
    static let shared = ConnectionAuditLog()
    private static let retentionSeconds: TimeInterval = 48 * 3600
    private static let maxEntries = 2000

    private static let claudeDomainSuffixes = [
        "anthropic.com",
        "claude.ai",
        "claude.com",
        "claudeusercontent.com",
        "challenges.cloudflare.com",
    ]

    private let fileURL: URL
    private var entries: [ConnectionAuditEntry] = []
    private var loaded = false

    init(stateDirectory: URL? = nil) {
        let dir = stateDirectory ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
            "Library/Application Support/local.claude-environment-check", isDirectory: true
        )
        self.fileURL = dir.appendingPathComponent("connection-audit.json")
    }

    static func isClaudeHost(_ host: String) -> Bool {
        let lower = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        for suffix in claudeDomainSuffixes {
            if lower == suffix || lower.hasSuffix(".\(suffix)") {
                return true
            }
        }
        return false
    }

    func append(_ entry: ConnectionAuditEntry) -> (stats: ConnectionAuditStats, recent: [ConnectionAuditEntry]) {
        ensureLoaded()
        entries.append(entry)
        prune(now: entry.startedAt)
        save()
        return (computeStats(), Array(entries.suffix(200).reversed()))
    }

    func snapshot(limit: Int = 200, now: Date = Date()) -> (stats: ConnectionAuditStats, recent: [ConnectionAuditEntry]) {
        ensureLoaded()
        prune(now: now)
        return (computeStats(), Array(entries.suffix(limit).reversed()))
    }

    func allEntries(now: Date = Date()) -> [ConnectionAuditEntry] {
        ensureLoaded()
        prune(now: now)
        return Array(entries.reversed())
    }

    func clear() {
        entries = []
        loaded = true
        try? FileManager.default.removeItem(at: fileURL)
    }

    func exportJSON() -> Data? {
        ensureLoaded()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try? encoder.encode(Array(entries.reversed()))
    }

    func exportCSV() -> String {
        ensureLoaded()
        let formatter = ISO8601DateFormatter()
        var rows: [String] = [
            "started_at,method,host,port,claude_domain,decision,exit_country,exit_ip,bytes_up,bytes_down,duration_ms,reason"
        ]
        for item in entries.reversed() {
            let fields: [String] = [
                formatter.string(from: item.startedAt),
                item.method,
                item.host,
                String(item.port),
                item.isClaudeDomain ? "true" : "false",
                item.decision.rawValue,
                item.exitCountry ?? "",
                item.exitIP ?? "",
                String(item.bytesUp),
                String(item.bytesDown),
                item.durationMs.map(String.init) ?? "",
                item.reason ?? "",
            ]
            rows.append(fields.map(csvEscape).joined(separator: ","))
        }
        return rows.joined(separator: "\n") + "\n"
    }

    private func csvEscape(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r") {
            return "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\""
        }
        return value
    }

    private func ensureLoaded() {
        guard !loaded else { return }
        loaded = true
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([ConnectionAuditEntry].self, from: data) else {
            return
        }
        entries = decoded
    }

    private func prune(now: Date) {
        let cutoff = now.addingTimeInterval(-Self.retentionSeconds)
        entries.removeAll { $0.startedAt < cutoff }
        if entries.count > Self.maxEntries {
            entries = Array(entries.suffix(Self.maxEntries))
        }
    }

    private func computeStats() -> ConnectionAuditStats {
        var allowed = 0
        var blocked = 0
        var upstreamErrors = 0
        var claudeTotal = 0
        for item in entries {
            if item.isClaudeDomain { claudeTotal += 1 }
            switch item.decision {
            case .allowed: allowed += 1
            case .blocked, .rejectedLoopback: blocked += 1
            case .upstreamError: upstreamErrors += 1
            }
        }
        return ConnectionAuditStats(
            total: entries.count,
            allowed: allowed,
            blocked: blocked,
            upstreamErrors: upstreamErrors,
            claudeTotal: claudeTotal
        )
    }

    private func save() {
        let dir = fileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        guard let data = try? JSONEncoder().encode(entries) else { return }
        let template = dir.appendingPathComponent(".connection-audit.XXXXXXXX").path
        var path = template.utf8CString
        let fd = path.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard fd >= 0 else { return }
        let tempPath = String(decoding: path.dropLast().map { UInt8(bitPattern: $0) }, as: UTF8.self)
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer {
            try? handle.close()
            _ = unlink(tempPath)
        }
        do {
            try handle.write(contentsOf: data)
            _ = fchmod(fd, 0o600)
            try handle.synchronize()
            _ = rename(tempPath, fileURL.path)
        } catch {
            // Non-fatal persistence error
        }
    }
}
