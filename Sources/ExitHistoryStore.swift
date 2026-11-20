import Darwin
import Foundation

struct ExitSample: Codable, Equatable, Identifiable, Sendable {
    let capturedAt: Date
    let ip: String
    let countryCode: String?
    let asn: Int?
    let org: String?
    let networkKind: ExitNetworkKind
    let probePath: String

    var id: String { "\(capturedAt.timeIntervalSince1970)-\(ip)" }
}

struct ExitDriftSummary: Codable, Equatable, Sendable {
    let retentionHours: Int
    let sampleCount: Int
    let uniqueIPCount: Int
    let ipChanges: Int
    let countryChanges: Int
    let guardedCountryChanges: Int
    let countries: [String]
    let recentSamples: [ExitSample]

    static let empty = ExitDriftSummary(
        retentionHours: 48,
        sampleCount: 0,
        uniqueIPCount: 0,
        ipChanges: 0,
        countryChanges: 0,
        guardedCountryChanges: 0,
        countries: [],
        recentSamples: []
    )
}

actor ExitHistoryStore {
    static let shared = ExitHistoryStore()
    private static let retentionSeconds: TimeInterval = 48 * 3600
    private static let maxSamples = 200

    private let fileURL: URL

    init(stateDirectory: URL? = nil) {
        let dir = stateDirectory ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
            "Library/Application Support/local.claude-environment-check", isDirectory: true
        )
        self.fileURL = dir.appendingPathComponent("exit-history.json")
    }

    func record(_ sample: ExitSample) -> ExitDriftSummary {
        var samples = prune(loadRaw(), now: sample.capturedAt)
        if let last = samples.last,
           last.ip == sample.ip,
           last.countryCode == sample.countryCode,
           last.probePath == sample.probePath,
           sample.capturedAt.timeIntervalSince(last.capturedAt) < 60 {
            samples[samples.count - 1] = sample
        } else {
            samples.append(sample)
        }
        if samples.count > Self.maxSamples {
            samples = Array(samples.suffix(Self.maxSamples))
        }
        save(samples)
        return summarize(samples)
    }

    func summary(now: Date = Date()) -> ExitDriftSummary {
        let samples = prune(loadRaw(), now: now)
        return summarize(samples)
    }

    func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }

    private func prune(_ samples: [ExitSample], now: Date) -> [ExitSample] {
        let cutoff = now.addingTimeInterval(-Self.retentionSeconds)
        return samples.filter { $0.capturedAt >= cutoff }.sorted { $0.capturedAt < $1.capturedAt }
    }

    private func summarize(_ samples: [ExitSample]) -> ExitDriftSummary {
        guard !samples.isEmpty else { return .empty }
        var ipChanges = 0
        var countryChanges = 0
        var guardedCountryChanges = 0
        var uniqueIPs: Set<String> = []
        var uniqueCountries: [String] = []
        var seenCountries: Set<String> = []
        var prevIP: String?
        var prevCountry: String?
        var prevGuardedCountry: String?

        for item in samples {
            uniqueIPs.insert(item.ip)
            if let prevIP, prevIP != item.ip {
                ipChanges += 1
            }
            prevIP = item.ip
            if let code = item.countryCode {
                if seenCountries.insert(code).inserted {
                    uniqueCountries.append(code)
                }
                if let prevCountry, prevCountry != code {
                    countryChanges += 1
                }
                prevCountry = code

                let isGuardedSample = item.probePath.contains("保护代理") || item.probePath.contains("熔断守卫")
                if isGuardedSample {
                    if let prevGuardedCountry, prevGuardedCountry != code {
                        guardedCountryChanges += 1
                    }
                    prevGuardedCountry = code
                }
            }
        }

        return ExitDriftSummary(
            retentionHours: 48,
            sampleCount: samples.count,
            uniqueIPCount: uniqueIPs.count,
            ipChanges: ipChanges,
            countryChanges: countryChanges,
            guardedCountryChanges: guardedCountryChanges,
            countries: uniqueCountries,
            recentSamples: Array(samples.suffix(12).reversed())
        )
    }

    private func loadRaw() -> [ExitSample] {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([ExitSample].self, from: data) else {
            return []
        }
        return decoded
    }

    private func save(_ samples: [ExitSample]) {
        let dir = fileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        guard let data = try? JSONEncoder().encode(samples) else { return }
        let template = dir.appendingPathComponent(".exit-history.XXXXXXXX").path
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
            // Non-fatal history persistence failure
        }
    }
}
