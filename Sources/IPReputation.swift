import dnssd
import Foundation

struct ReputationVote: Codable, Equatable, Identifiable, Sendable {
    enum Category: String, Codable, Sendable {
        case blacklist
        case tor
        case residentialPBL
        case hostingOrProxy
    }

    enum Outcome: String, Codable, Sendable {
        case clean
        case flagged
        case unavailable
    }

    let id: String
    let source: String
    let category: Category
    let outcome: Outcome
    let detail: String?
}

struct IPReputationReport: Codable, Equatable, Sendable {
    let ip: String
    let votes: [ReputationVote]
    let blacklistChecked: Int
    let blacklistHits: Int
    let isTorExit: Bool
    let isSpamhausSevere: Bool
    let hostingSignals: Int
    let severity: ReadingSeverity
    let headline: String
    let detail: String
}

enum IPReputationProber {
    /// Reverses an IPv4 dotted-quad into DNSBL lookup format (`1.2.3.4` -> `4.3.2.1`). Returns `nil` for non-IPv4.
    static func reverseIPv4(_ ip: String) -> String? {
        let parts = ip.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var nums: [Int] = []
        for p in parts {
            guard let n = Int(p), (0...255).contains(n), String(n) == String(p) else { return nil }
            nums.append(n)
        }
        return nums.reversed().map(String.init).joined(separator: ".")
    }

    /// Classifies Spamhaus ZEN DNSBL return codes accurately:
    /// - `127.255.255.252/.254/.255` = public resolver query refused -> `.unavailable` (never a false positive!)
    /// - `127.0.0.10/.11` = Policy Block List (residential dynamic IP) -> `.clean` (good for Claude!)
    /// - `127.0.0.2/.3/.4/.9` = SBL / CSS / XBL / DROP real abuse listing -> `.flagged`
    static func classifySpamhausZen(returnIPs: [String]) -> ReputationVote {
        if returnIPs.isEmpty {
            return ReputationVote(id: "spamhaus-zen", source: "Spamhaus ZEN", category: .blacklist, outcome: .clean, detail: "未命中")
        }
        let refusedCodes = Set(["127.255.255.252", "127.255.255.254", "127.255.255.255"])
        if returnIPs.allSatisfy({ refusedCodes.contains($0) }) {
            return ReputationVote(id: "spamhaus-zen", source: "Spamhaus ZEN", category: .blacklist, outcome: .unavailable, detail: "公共 DNS 限流跳过")
        }
        let validCodes = returnIPs.filter { !refusedCodes.contains($0) }
        var severeLabels: [String] = []
        var hasPBL = false
        for code in validCodes {
            switch code {
            case "127.0.0.2": severeLabels.append("SBL")
            case "127.0.0.3": severeLabels.append("CSS")
            case "127.0.0.4": severeLabels.append("XBL")
            case "127.0.0.9": severeLabels.append("DROP")
            case "127.0.0.10", "127.0.0.11": hasPBL = true
            default:
                if code.hasPrefix("127.0.0.") {
                    severeLabels.append(code)
                }
            }
        }
        if !severeLabels.isEmpty {
            return ReputationVote(
                id: "spamhaus-zen",
                source: "Spamhaus ZEN",
                category: .blacklist,
                outcome: .flagged,
                detail: "命中 \(severeLabels.joined(separator: "/")) 滥用库"
            )
        }
        if hasPBL {
            return ReputationVote(
                id: "spamhaus-zen",
                source: "Spamhaus ZEN",
                category: .residentialPBL,
                outcome: .clean,
                detail: "PBL 动态家宽段（非黑名单）"
            )
        }
        return ReputationVote(id: "spamhaus-zen", source: "Spamhaus ZEN", category: .blacklist, outcome: .clean, detail: "未命中")
    }

    static func classifySpamhausDrop(returnIPs: [String]) -> ReputationVote {
        if returnIPs.isEmpty {
            return ReputationVote(id: "spamhaus-drop", source: "Spamhaus DROP", category: .blacklist, outcome: .clean, detail: "未命中")
        }
        let refusedCodes = Set(["127.255.255.252", "127.255.255.254", "127.255.255.255"])
        if returnIPs.allSatisfy({ refusedCodes.contains($0) }) {
            return ReputationVote(id: "spamhaus-drop", source: "Spamhaus DROP", category: .blacklist, outcome: .unavailable, detail: "公共 DNS 限流跳过")
        }
        let hits = returnIPs.filter { $0.hasPrefix("127.0.0.") }
        if !hits.isEmpty {
            return ReputationVote(id: "spamhaus-drop", source: "Spamhaus DROP", category: .blacklist, outcome: .flagged, detail: "命中 DROP 高危网段")
        }
        return ReputationVote(id: "spamhaus-drop", source: "Spamhaus DROP", category: .blacklist, outcome: .clean, detail: "未命中")
    }

    static func classifyTorExit(returnIPs: [String]) -> ReputationVote {
        if returnIPs.contains("127.0.0.2") {
            return ReputationVote(id: "tor-exit", source: "Tor 出口库", category: .tor, outcome: .flagged, detail: "确认为 Tor 匿名出口")
        }
        return ReputationVote(id: "tor-exit", source: "Tor 出口库", category: .tor, outcome: .clean, detail: "未命中")
    }

    static func classifyDroneBL(returnIPs: [String]) -> ReputationVote {
        let hits = returnIPs.filter { $0.hasPrefix("127.0.0.") }
        if !hits.isEmpty {
            return ReputationVote(id: "dronebl", source: "DroneBL", category: .blacklist, outcome: .flagged, detail: "命中开放代理/僵尸主机库 (\(hits.joined(separator: ",")))")
        }
        return ReputationVote(id: "dronebl", source: "DroneBL", category: .blacklist, outcome: .clean, detail: "未命中")
    }

    static func classifyUCEProtect(returnIPs: [String]) -> ReputationVote {
        if returnIPs.contains("127.0.0.2") {
            return ReputationVote(id: "uceprotect-l1", source: "UCEPROTECT L1", category: .blacklist, outcome: .flagged, detail: "命中单 IP 滥用记录")
        }
        return ReputationVote(id: "uceprotect-l1", source: "UCEPROTECT L1", category: .blacklist, outcome: .clean, detail: "未命中")
    }

    /// Scientific multi-source consensus voting — avoids single-source false alarms (like IPQS over-flagging).
    static func synthesize(ip: String, votes: [ReputationVote]) -> IPReputationReport {
        let blacklistVotes = votes.filter { $0.category == .blacklist || $0.category == .residentialPBL || $0.category == .tor }
        let checked = blacklistVotes.filter { $0.outcome != .unavailable }
        let flaggedBL = checked.filter { $0.outcome == .flagged }
        let isTor = votes.contains { $0.category == .tor && $0.outcome == .flagged }
        let isSpamhausSevere = votes.contains {
            ($0.id == "spamhaus-zen" || $0.id == "spamhaus-drop") && $0.outcome == .flagged
        }
        let hostingVotes = votes.filter { $0.category == .hostingOrProxy && $0.outcome == .flagged }

        let severity: ReadingSeverity
        let headline: String
        let detail: String

        let flaggedNames = flaggedBL.map { "\($0.source)\($0.detail.map { "(\($0))" } ?? "")" }
        let checkedCount = checked.count

        if isTor {
            severity = .danger
            headline = "高危 · 命中 Tor 匿名出口（\(flaggedBL.count)/\(checkedCount)）"
            detail = "命中来源：\(flaggedNames.joined(separator: "、"))。Anthropic / Cloudflare 对 Tor 出口极易直接封禁，请立即更换节点。"
        } else if isSpamhausSevere || flaggedBL.count >= 2 {
            severity = .danger
            headline = "高危 · 多源/权威黑名单命中（\(flaggedBL.count)/\(checkedCount)）"
            detail = "命中来源：\(flaggedNames.joined(separator: "、"))。建议更换更干净的独享/低滥用节点。"
        } else if flaggedBL.count == 1 {
            severity = .caution
            headline = "单源轻微命中（1/\(checkedCount)）· 多数库干净"
            detail = "仅 \(flaggedNames.joined(separator: "、")) 命中，其余 \(max(0, checkedCount - 1)) 个权威库全绿（单源易误报，可继续观察或按需换节点）。"
        } else if checkedCount == 0 {
            severity = .neutral
            headline = "黑名单探测受限"
            detail = "当前递归 DNS 拒绝了全部 DNSBL 查询，未产生负面判定。"
        } else if !hostingVotes.isEmpty {
            severity = .ok
            headline = "权威黑名单全绿（0/\(checkedCount) 命中）· 云/机房段"
            let hostNote = hostingVotes.compactMap(\.detail).joined(separator: "；")
            detail = "已检 \(checkedCount) 个权威库全部干净（\(checked.map(\.source).joined(separator: " / "))）；\(hostNote.isEmpty ? "ASN 特征偏向云/托管段" : hostNote)。"
        } else {
            severity = .ok
            headline = "纯净 · 权威黑名单全绿（0/\(checkedCount) 命中）"
            let pblNote = votes.first(where: { $0.category == .residentialPBL })?.detail.map { " · \($0)" } ?? ""
            detail = "已检 \(checkedCount) 个权威黑名单与 Tor 库均未命中（\(checked.map(\.source).joined(separator: " / "))）\(pblNote)。"
        }

        return IPReputationReport(
            ip: ip,
            votes: votes,
            blacklistChecked: checkedCount,
            blacklistHits: flaggedBL.count,
            isTorExit: isTor,
            isSpamhausSevere: isSpamhausSevere,
            hostingSignals: hostingVotes.count,
            severity: severity,
            headline: headline,
            detail: detail
        )
    }

    static func probe(ip: String, geo: MultiSourceGeoReport?) async -> IPReputationReport? {
        guard let rev = reverseIPv4(ip) else { return nil }

        async let zenIPs = queryARecords(domain: "\(rev).zen.spamhaus.org", timeout: 2.5)
        async let dropIPs = queryARecords(domain: "\(rev).drop.spamhaus.org", timeout: 2.5)
        async let torIPs = queryARecords(domain: "\(rev).dnsel.torproject.org", timeout: 2.5)
        async let droneIPs = queryARecords(domain: "\(rev).dnsbl.dronebl.org", timeout: 2.5)
        async let uceIPs = queryARecords(domain: "\(rev).dnsbl-1.uceprotect.net", timeout: 2.5)

        var votes: [ReputationVote] = [
            classifySpamhausZen(returnIPs: await zenIPs),
            classifySpamhausDrop(returnIPs: await dropIPs),
            classifyTorExit(returnIPs: await torIPs),
            classifyDroneBL(returnIPs: await droneIPs),
            classifyUCEProtect(returnIPs: await uceIPs),
        ]

        if let geo, geo.networkKind == .hosting {
            let meta = [geo.networkASN.map { "AS\($0)" }, geo.networkOrg].compactMap { $0 }.joined(separator: " ")
            votes.append(ReputationVote(
                id: "asn-hosting",
                source: "ASN 机房段特征",
                category: .hostingOrProxy,
                outcome: .flagged,
                detail: meta.isEmpty ? "识别为云/机房段" : "\(meta) 偏向云/机房段"
            ))
        }

        return synthesize(ip: ip, votes: votes)
    }

    // MARK: - Native dnssd A-record DNSBL Lookup

    private final class AQueryContext: @unchecked Sendable {
        let lock = NSLock()
        var results: [String] = []
        var finished = false
        var serviceRef: DNSServiceRef?
        var timer: DispatchSourceTimer?
        var continuation: CheckedContinuation<[String], Never>?
        var selfRetention: Unmanaged<AQueryContext>?

        func finish() {
            var cont: CheckedContinuation<[String], Never>?
            var ref: DNSServiceRef?
            var retention: Unmanaged<AQueryContext>?
            var out: [String] = []
            lock.withLock {
                guard !finished else { return }
                finished = true
                cont = continuation
                continuation = nil
                ref = serviceRef
                serviceRef = nil
                timer?.cancel()
                timer = nil
                retention = selfRetention
                selfRetention = nil
                out = results
            }
            if let ref { DNSServiceRefDeallocate(ref) }
            retention?.release()
            cont?.resume(returning: out)
        }
    }

    private static let aQueryCallback: DNSServiceQueryRecordReply = {
        _, flags, _, errorCode, _, rrtype, _, rdlen, rdata, _, ctxPtr in
        guard let ctxPtr else { return }
        let ctx = Unmanaged<AQueryContext>.fromOpaque(ctxPtr).takeUnretainedValue()
        if errorCode == kDNSServiceErr_NoError,
           rrtype == UInt16(kDNSServiceType_A),
           rdlen == 4,
           let rdata {
            let bytes = rdata.assumingMemoryBound(to: UInt8.self)
            let ipStr = "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"
            ctx.lock.withLock {
                if !ctx.results.contains(ipStr) {
                    ctx.results.append(ipStr)
                }
            }
        }
        if errorCode != kDNSServiceErr_NoError || (flags & DNSServiceFlags(kDNSServiceFlagsMoreComing)) == 0 {
            ctx.finish()
        }
    }

    private static func queryARecords(domain: String, timeout: TimeInterval) async -> [String] {
        await withCheckedContinuation { continuation in
            let queue = DispatchQueue(label: "local.claude-env-check.dnsbl.\(UUID().uuidString)")
            let ctx = AQueryContext()
            ctx.continuation = continuation
            let retained = Unmanaged.passRetained(ctx)
            ctx.selfRetention = retained

            var sdRef: DNSServiceRef?
            let err = DNSServiceQueryRecord(
                &sdRef,
                0,
                0,
                domain,
                UInt16(kDNSServiceType_A),
                UInt16(kDNSServiceClass_IN),
                Self.aQueryCallback,
                retained.toOpaque()
            )
            guard err == kDNSServiceErr_NoError, let sdRef else {
                ctx.finish()
                return
            }
            ctx.lock.withLock { ctx.serviceRef = sdRef }
            guard DNSServiceSetDispatchQueue(sdRef, queue) == kDNSServiceErr_NoError else {
                ctx.finish()
                return
            }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + timeout)
            timer.setEventHandler { ctx.finish() }
            ctx.lock.withLock { ctx.timer = timer }
            timer.resume()
        }
    }
}
