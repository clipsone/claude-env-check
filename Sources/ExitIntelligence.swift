import CFNetwork
import Darwin
import dnssd
import Foundation

enum ExitNetworkKind: String, Codable, Equatable, Sendable {
    case residential
    case hosting
    case unknown

    var label: String {
        switch self {
        case .residential: "住宅 / 宽带网络（推断）"
        case .hosting: "数据中心 / 云机房（推断）"
        case .unknown: "网络属性未明确分类"
        }
    }
}

struct GeoSourceResult: Codable, Equatable, Sendable {
    let source: String
    let ip: String?
    let countryCode: String?
    let regionName: String?
    let city: String?
    let asn: Int?
    let org: String?
    let timeZone: String?
    let colo: String?
    let warp: String?
    let error: String?

    var isUsable: Bool {
        error == nil && countryCode != nil
    }

    var formattedASN: String? {
        asn.map { "AS\($0)" }
    }
}

enum GeoConsensus: Equatable, Sendable {
    case consistent(countryCode: String, agreeingCount: Int, totalAttempted: Int)
    case split(countries: [String], details: [(source: String, countryCode: String)])
    case singleSource(countryCode: String, source: String)
    case unavailable

    static func == (lhs: GeoConsensus, rhs: GeoConsensus) -> Bool {
        switch (lhs, rhs) {
        case let (.consistent(a1, a2, a3), .consistent(b1, b2, b3)):
            return a1 == b1 && a2 == b2 && a3 == b3
        case let (.split(a1, a2), .split(b1, b2)):
            return a1 == b1 && a2.map(\.source) == b2.map(\.source) && a2.map(\.countryCode) == b2.map(\.countryCode)
        case let (.singleSource(a1, a2), .singleSource(b1, b2)):
            return a1 == b1 && a2 == b2
        case (.unavailable, .unavailable):
            return true
        default:
            return false
        }
    }
}

struct MultiSourceGeoReport: Sendable {
    let sources: [GeoSourceResult]
    let primary: GeoSourceResult?
    let consensus: GeoConsensus
    let networkKind: ExitNetworkKind
    let networkOrg: String?
    let networkASN: Int?
    let cloudflareColo: String?
    let cloudflareWarp: String?

    var primaryCountryCode: String? {
        switch consensus {
        case let .consistent(code, _, _): return code
        case let .singleSource(code, _): return code
        case .split: return primary?.countryCode
        case .unavailable: return nil
        }
    }

    var primaryIP: String? {
        primary?.ip ?? sources.compactMap(\.ip).first
    }

    var primaryTimeZone: String? {
        sources.compactMap(\.timeZone).first
    }
}

struct DualStackReport: Sendable {
    let ipv4: String?
    let ipv6: String?
    let ipv6Geo: GeoSourceResult?
    let ipv6Checked: Bool
}

struct DNSProbeReport: Sendable {
    let fakeIPAddress: String?
    let fakeIPDomain: String
    let recursiveResolverIP: String?
    let secondaryResolverIP: String?
    let ecsSubnet: String?
    let resolverGeo: GeoSourceResult?
    let ecsGeo: GeoSourceResult?
    let probeSource: String?
}

enum ExitClassifier {
    /// Unified, single-source-of-truth set of cloud, VPS, CDN, and datacenter ASNs.
    static let hostingASNs: Set<Int> = [
        906,    // DMIT
        8075,   // Microsoft Azure
        9009,   // M247
        12876,  // Scaleway
        13335,  // Cloudflare
        14061,  // DigitalOcean
        14618,  // Amazon AWS
        15169,  // Google
        16265,  // Leaseweb
        16276,  // OVH
        16509,  // Amazon AWS
        20473,  // Vultr / Choopa
        21859,  // Zenlayer
        24940,  // Hetzner
        25820,  // IT7 / Bandwagon
        28753,  // Leaseweb
        31898,  // Oracle Cloud
        36007,  // Kamatera
        36352,  // ColoCrossing / RackNerd
        37963,  // Alibaba Cloud
        45090,  // Tencent Cloud
        45102,  // Alibaba Cloud
        45103,  // Alibaba Cloud
        47583,  // Hostinger
        51167,  // Contabo
        53667,  // BuyVM / FranTech
        60068,  // Datacamp
        60781,  // Leaseweb
        63949,  // Akamai / Linode
        132203, // Tencent Cloud
        135377, // UCloud
        136907, // Huawei Cloud
        199524, // Gcore
        396982, // Google Cloud
    ]

    /// Known global Anycast public DNS resolver ASNs (used for contextual DNS note).
    static let anycastDNSASNs: Set<Int> = [
        13335,  // Cloudflare 1.1.1.1
        15169,  // Google 8.8.8.8
        19281,  // Quad9 9.9.9.9
        36692,  // Cisco OpenDNS
    ]

    private static let rirKeywords = [
        "apnic", "arin", "ripe ncc", "lacnic", "afrinic", "jpnic",
        "network information center", "network information centre",
        "american registry for internet numbers", "ripe network coordination"
    ]

    private static let hostingKeywords = [
        "amazon", "aws", "azure", "microsoft", "digitalocean", "vultr", "choopa",
        "hetzner", "linode", "akamai", "ovh", "oracle", "alibaba", "aliyun",
        "tencent", "huawei", "ucloud", "cloudflare", "fastly", "contabo",
        "m247", "leaseweb", "datacamp", "hostinger", "racknerd", "bandwagon",
        "zenlayer", "scaleway", "gcore", "dmit", "colocrossing", "frantech",
        "datacenter", "data center", "data centre", "colocation", "hosting", "vps"
    ]

    private static let broadbandKeywords = [
        "comcast", "xfinity", "charter", "spectrum", "cox communications",
        "verizon", "at&t", "google fiber", "rogers", "bell canada", "shaw communications",
        "telus", "ntt", "kddi", "softbank", "biglobe", "sony network",
        "korea telecom", "kt corporation", "sk broadband", "lg uplus", "lg powercomm",
        "singtel", "starhub", "m1 limited", "myrepublic",
        "chunghwa telecom", "hinet", "taiwan mobile", "far eastone",
        "deutsche telekom", "vodafone", "british telecommunications", "bt public",
        "virgin media", "sky uk", "orange", "free sas", "kpn", "ziggo",
        "swisscom", "telstra", "optus", "tpg", "spark new zealand",
        "china telecom", "china unicom", "china mobile", "chinatelecom",
        "中国电信", "中国联通", "中国移动", "中华电信"
    ]

    static func isRIRPlaceholder(_ org: String?) -> Bool {
        guard let lower = org?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !lower.isEmpty else {
            return true
        }
        return rirKeywords.contains { lower.contains($0) }
    }

    static func classify(asn: Int?, org: String?) -> ExitNetworkKind {
        let lower = org?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        if lower.contains("google fiber") {
            return .residential
        }
        if let asn, hostingASNs.contains(asn) {
            return .hosting
        }
        if !lower.isEmpty {
            if lower.contains("google") && !lower.contains("fiber") {
                return .hosting
            }
            if hostingKeywords.contains(where: { lower.contains($0) }) {
                return .hosting
            }
            if broadbandKeywords.contains(where: { lower.contains($0) }) {
                return .residential
            }
        }
        return .unknown
    }

    static func parseASN(_ raw: String?) -> Int? {
        guard let raw else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if let direct = Int(trimmed), direct > 0 { return direct }
        if trimmed.hasPrefix("AS") {
            let digits = trimmed.dropFirst(2).prefix(while: \.isNumber)
            if let value = Int(digits), value > 0 { return value }
        }
        return nil
    }
}

enum ExitProbes {
    private static let cfTraceURL = URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!
    private static let ipWhoURL = URL(string: "https://ipwho.is/")!
    private static let ipInfoURL = URL(string: "https://ipinfo.io/json")!
    private static let ipSBURL = URL(string: "https://api.ip.sb/geoip")!
    private static let ipifyV4URL = URL(string: "https://api4.ipify.org?format=json")!
    private static let ipifyV6URL = URL(string: "https://api6.ipify.org?format=json")!

    static func probeMultiSourceGeo(
        proxyPort: Int?,
        proxyProtocol: UpstreamProxyProtocol = .httpConnect
    ) async -> MultiSourceGeoReport {
        async let cf = fetchCloudflareTrace(proxyPort: proxyPort, proxyProtocol: proxyProtocol)
        async let ipWho = fetchIPWho(ip: nil, proxyPort: proxyPort, proxyProtocol: proxyProtocol)
        async let third = fetchIPInfoOrFallback(ip: nil, proxyPort: proxyPort, proxyProtocol: proxyProtocol)

        let sources = [await ipWho, await third, await cf]
        let usable = sources.filter(\.isUsable)

        // Pick richest GeoIP source as primary (prefer ipwho.is / ipinfo.io / ip.sb over CF trace which lacks ASN/city)
        let primary = usable.first { $0.source != "Cloudflare Trace" } ?? usable.first

        // Compute mathematically exact multi-source country consensus
        let countryPairs: [(source: String, countryCode: String)] = usable.compactMap { item in
            guard let code = item.countryCode else { return nil }
            return (item.source, code)
        }
        let uniqueCountries = Array(Set(countryPairs.map(\.countryCode))).sorted()
        let consensus: GeoConsensus
        if countryPairs.isEmpty {
            consensus = .unavailable
        } else if uniqueCountries.count > 1 {
            consensus = .split(countries: uniqueCountries, details: countryPairs)
        } else if countryPairs.count >= 2, let code = uniqueCountries.first {
            consensus = .consistent(countryCode: code, agreeingCount: countryPairs.count, totalAttempted: sources.count)
        } else if let first = countryPairs.first {
            consensus = .singleSource(countryCode: first.countryCode, source: first.source)
        } else {
            consensus = .unavailable
        }

        // Choose best organization / ASN (skip RIR placeholders when another source for same IP/ASN has real ISP)
        let bestASN = primary?.asn ?? usable.compactMap(\.asn).first
        let bestOrg: String? = {
            if let org = primary?.org, !ExitClassifier.isRIRPlaceholder(org) {
                return org
            }
            for item in usable {
                if let org = item.org, !ExitClassifier.isRIRPlaceholder(org) {
                    if primary?.ip == nil || item.ip == nil || item.ip == primary?.ip || item.asn == bestASN {
                        return org
                    }
                }
            }
            return primary?.org ?? usable.compactMap(\.org).first
        }()
        let networkKind = ExitClassifier.classify(asn: bestASN, org: bestOrg)

        let cfResult = sources.first { $0.source == "Cloudflare Trace" }
        return MultiSourceGeoReport(
            sources: sources,
            primary: primary,
            consensus: consensus,
            networkKind: networkKind,
            networkOrg: bestOrg,
            networkASN: bestASN,
            cloudflareColo: cfResult?.colo,
            cloudflareWarp: cfResult?.warp
        )
    }

    static func probeDualStack(proxyPort: Int?) async -> DualStackReport {
        async let v4 = fetchIpify(ipifyV4URL, proxyPort: proxyPort, expectIPv6: false)
        async let v6 = fetchIpify(ipifyV6URL, proxyPort: proxyPort, expectIPv6: true)
        let ipv4 = await v4
        let ipv6 = await v6
        let ipv6Geo: GeoSourceResult?
        if let ipv6 {
            ipv6Geo = await lookupIP(ipv6, proxyPort: proxyPort)
        } else {
            ipv6Geo = nil
        }
        return DualStackReport(ipv4: ipv4, ipv6: ipv6, ipv6Geo: ipv6Geo, ipv6Checked: true)
    }

    static func probeDNSLeak(proxyPort: Int?) async -> DNSProbeReport {
        let token = UUID().uuidString.prefix(8).lowercased()
        let fakeDomain = "egcheck-\(token).claude.ai"

        let fakeIPTask = Task.detached(priority: .userInitiated) {
            resolveFirstIPv4(host: fakeDomain)
        }
        async let akaTask = queryTXTRecords(name: "whoami.ds.akahelp.net")
        async let googleTask = queryTXTRecords(name: "o-o.myaddr.l.google.com")

        let fakeIP = await fakeIPTask.value
        let akaLines = await akaTask
        let googleLines = await googleTask

        let parsedAka = parseAkamaiWhoami(akaLines)
        let googleIP = parseFirstIP(from: googleLines)

        let primaryResolverIP = parsedAka.ns ?? parsedAka.ip ?? googleIP
        let secondaryResolverIP = (googleIP != nil && googleIP != primaryResolverIP) ? googleIP : nil
        let ecsIP = parsedAka.ecsSubnet.flatMap(extractIPFromCIDR)

        let probeSource: String?
        if parsedAka.ns != nil || parsedAka.ip != nil {
            probeSource = "whoami.ds.akahelp.net"
        } else if googleIP != nil {
            probeSource = "o-o.myaddr.l.google.com"
        } else {
            probeSource = nil
        }

        async let resolverGeoTask: GeoSourceResult? = {
            guard let ip = primaryResolverIP, isPublicIP(ip) else { return nil }
            return await lookupIP(ip, proxyPort: proxyPort)
        }()
        async let ecsGeoTask: GeoSourceResult? = {
            guard let ip = ecsIP, isPublicIP(ip) else { return nil }
            return await lookupIP(ip, proxyPort: proxyPort)
        }()

        return DNSProbeReport(
            fakeIPAddress: fakeIP,
            fakeIPDomain: fakeDomain,
            recursiveResolverIP: primaryResolverIP,
            secondaryResolverIP: secondaryResolverIP,
            ecsSubnet: parsedAka.ecsSubnet,
            resolverGeo: await resolverGeoTask,
            ecsGeo: await ecsGeoTask,
            probeSource: probeSource
        )
    }

    static func lookupIP(_ ip: String, proxyPort: Int?) async -> GeoSourceResult? {
        let cleaned = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidIP(cleaned) else { return nil }
        let primary = await fetchIPWho(ip: cleaned, proxyPort: proxyPort)
        if primary.isUsable { return primary }
        let fallback = await fetchIPInfoOrFallback(ip: cleaned, proxyPort: proxyPort)
        return fallback.isUsable ? fallback : nil
    }

    // MARK: - HTTP Geo Providers

    private static func fetchCloudflareTrace(proxyPort: Int?, proxyProtocol: UpstreamProxyProtocol = .httpConnect) async -> GeoSourceResult {
        do {
            let (data, response) = try await Diagnostics.httpRequest(cfTraceURL, proxyPort: proxyPort, proxyProtocol: proxyProtocol, timeout: 6)
            guard response.statusCode == 200, let text = String(data: data, encoding: .utf8) else {
                return GeoSourceResult(source: "Cloudflare Trace", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                       asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil,
                                       error: "HTTP \(response.statusCode)")
            }
            var fields: [String: String] = [:]
            for line in text.split(whereSeparator: \.isNewline) {
                guard let eq = line.firstIndex(of: "=") else { continue }
                let k = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
                let v = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                fields[k] = v
            }
            let ip = fields["ip"].flatMap { isValidIP($0) ? $0 : nil }
            let loc = ClaudeRegions.normalize(fields["loc"])
            return GeoSourceResult(
                source: "Cloudflare Trace",
                ip: ip,
                countryCode: loc,
                regionName: nil,
                city: nil,
                asn: nil,
                org: nil,
                timeZone: nil,
                colo: fields["colo"],
                warp: fields["warp"],
                error: loc == nil ? "无地区字段" : nil
            )
        } catch {
            return GeoSourceResult(source: "Cloudflare Trace", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                   asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil, error: error.localizedDescription)
        }
    }

    private static func fetchIPWho(ip: String?, proxyPort: Int?, proxyProtocol: UpstreamProxyProtocol = .httpConnect) async -> GeoSourceResult {
        let url: URL
        if let ip, let encoded = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
           let built = URL(string: "https://ipwho.is/\(encoded)") {
            url = built
        } else {
            url = ipWhoURL
        }
        do {
            let (data, response) = try await Diagnostics.httpRequest(url, headers: ["Accept": "application/json"],
                                                                     proxyPort: proxyPort, proxyProtocol: proxyProtocol, timeout: 6)
            guard response.statusCode == 200,
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                return GeoSourceResult(source: "ipwho.is", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                       asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil,
                                       error: "HTTP \(response.statusCode)")
            }
            if let success = json["success"] as? Bool, !success {
                return GeoSourceResult(source: "ipwho.is", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                       asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil,
                                       error: (json["message"] as? String) ?? "查询失败")
            }
            let conn = json["connection"] as? [String: Any]
            let tz = json["timezone"] as? [String: Any]
            let parsedIP = (json["ip"] as? String).flatMap { isValidIP($0) ? $0 : nil }
            let code = ClaudeRegions.normalize(json["country_code"] as? String)
            let asnValue: Int? = {
                if let n = conn?["asn"] as? Int, n > 0 { return n }
                if let s = conn?["asn"] as? String { return ExitClassifier.parseASN(s) }
                return nil
            }()
            let org = nonEmpty(conn?["org"] as? String) ?? nonEmpty(conn?["isp"] as? String)
            return GeoSourceResult(
                source: "ipwho.is",
                ip: parsedIP,
                countryCode: code,
                regionName: nonEmpty(json["region"] as? String),
                city: nonEmpty(json["city"] as? String),
                asn: asnValue,
                org: org,
                timeZone: nonEmpty(tz?["id"] as? String),
                colo: nil,
                warp: nil,
                error: code == nil ? "无国家码" : nil
            )
        } catch {
            return GeoSourceResult(source: "ipwho.is", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                   asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil, error: error.localizedDescription)
        }
    }

    private static func fetchIPInfoOrFallback(ip: String?, proxyPort: Int?, proxyProtocol: UpstreamProxyProtocol = .httpConnect) async -> GeoSourceResult {
        let info = await fetchIPInfo(ip: ip, proxyPort: proxyPort, proxyProtocol: proxyProtocol)
        if info.isUsable { return info }
        let sb = await fetchIPSB(ip: ip, proxyPort: proxyPort, proxyProtocol: proxyProtocol)
        return sb.isUsable ? sb : info
    }

    private static func fetchIPInfo(ip: String?, proxyPort: Int?, proxyProtocol: UpstreamProxyProtocol = .httpConnect) async -> GeoSourceResult {
        let url: URL
        if let ip, let encoded = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
           let built = URL(string: "https://ipinfo.io/\(encoded)/json") {
            url = built
        } else {
            url = ipInfoURL
        }
        do {
            let (data, response) = try await Diagnostics.httpRequest(url, headers: ["Accept": "application/json"],
                                                                     proxyPort: proxyPort, proxyProtocol: proxyProtocol, timeout: 6)
            guard response.statusCode == 200,
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                return GeoSourceResult(source: "ipinfo.io", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                       asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil,
                                       error: "HTTP \(response.statusCode)")
            }
            let parsedIP = (json["ip"] as? String).flatMap { isValidIP($0) ? $0 : nil }
            let code = ClaudeRegions.normalize(json["country"] as? String)
            let rawOrg = nonEmpty(json["org"] as? String)
            let asn = rawOrg.flatMap { token -> Int? in
                guard let first = token.split(separator: " ").first else { return nil }
                return ExitClassifier.parseASN(String(first))
            }
            let cleanedOrg: String? = {
                guard let rawOrg else { return nil }
                let parts = rawOrg.split(separator: " ", maxSplits: 1)
                if parts.count == 2, ExitClassifier.parseASN(String(parts[0])) != nil {
                    return String(parts[1]).trimmingCharacters(in: .whitespaces)
                }
                return rawOrg
            }()
            return GeoSourceResult(
                source: "ipinfo.io",
                ip: parsedIP,
                countryCode: code,
                regionName: nonEmpty(json["region"] as? String),
                city: nonEmpty(json["city"] as? String),
                asn: asn,
                org: cleanedOrg,
                timeZone: nonEmpty(json["timezone"] as? String),
                colo: nil,
                warp: nil,
                error: code == nil ? "无国家码" : nil
            )
        } catch {
            return GeoSourceResult(source: "ipinfo.io", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                   asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil, error: error.localizedDescription)
        }
    }

    private static func fetchIPSB(ip: String?, proxyPort: Int?, proxyProtocol: UpstreamProxyProtocol = .httpConnect) async -> GeoSourceResult {
        let url: URL
        if let ip, let encoded = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
           let built = URL(string: "https://api.ip.sb/geoip/\(encoded)") {
            url = built
        } else {
            url = ipSBURL
        }
        do {
            let (data, response) = try await Diagnostics.httpRequest(
                url,
                headers: ["Accept": "application/json", "User-Agent": "ClaudeEnvironmentCheck/1.2"],
                proxyPort: proxyPort,
                proxyProtocol: proxyProtocol,
                timeout: 6
            )
            guard response.statusCode == 200,
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                return GeoSourceResult(source: "api.ip.sb", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                       asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil,
                                       error: "HTTP \(response.statusCode)")
            }
            let parsedIP = (json["ip"] as? String).flatMap { isValidIP($0) ? $0 : nil }
            let code = ClaudeRegions.normalize(json["country_code"] as? String)
            let asn = (json["asn"] as? Int).flatMap { $0 > 0 ? $0 : nil }
            let org = nonEmpty(json["asn_organization"] as? String)
                ?? nonEmpty(json["organization"] as? String)
                ?? nonEmpty(json["isp"] as? String)
            return GeoSourceResult(
                source: "api.ip.sb",
                ip: parsedIP,
                countryCode: code,
                regionName: nonEmpty(json["region"] as? String),
                city: nonEmpty(json["city"] as? String),
                asn: asn,
                org: org,
                timeZone: nonEmpty(json["timezone"] as? String),
                colo: nil,
                warp: nil,
                error: code == nil ? "无国家码" : nil
            )
        } catch {
            return GeoSourceResult(source: "api.ip.sb", ip: nil, countryCode: nil, regionName: nil, city: nil,
                                   asn: nil, org: nil, timeZone: nil, colo: nil, warp: nil, error: error.localizedDescription)
        }
    }

    private static func fetchIpify(_ url: URL, proxyPort: Int?, expectIPv6: Bool) async -> String? {
        do {
            let (data, response) = try await Diagnostics.httpRequest(url, headers: ["Accept": "application/json"],
                                                                     proxyPort: proxyPort, timeout: 4.5)
            guard response.statusCode == 200,
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let ip = json["ip"] as? String else {
                return nil
            }
            if expectIPv6 {
                return isIPv6(ip) ? ip : nil
            } else {
                return isIPv4(ip) ? ip : nil
            }
        } catch {
            return nil
        }
    }

    // MARK: - Native DNS Probing (mDNSResponder via dnssd + dig fallback)

    static func resolveFirstIPv4(host: String) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else {
            return nil
        }
        defer { freeaddrinfo(first) }
        var addr = first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    static func isFakeIP(_ ipv4: String) -> Bool {
        var addr = in_addr()
        guard inet_pton(AF_INET, ipv4, &addr) == 1 else { return false }
        let hostOrder = UInt32(bigEndian: addr.s_addr)
        // RFC 2544 benchmark range 198.18.0.0/15 used by Clash/Mihomo/Surge TUN Fake-IP
        return (hostOrder & 0xFFFE_0000) == 0xC612_0000
    }

    private static func queryTXTRecords(name: String) async -> [String] {
        let native = await queryTXTViaMDNSResponder(name: name, timeoutSeconds: 3.5)
        if !native.isEmpty { return native }
        return await Task.detached(priority: .userInitiated) {
            queryTXTViaDig(name: name)
        }.value
    }

    private final class TXTQueryContext: @unchecked Sendable {
        let lock = NSLock()
        var serviceRef: DNSServiceRef?
        var records: [String] = []
        var finished = false
        var continuation: CheckedContinuation<[String], Never>?
        var timer: DispatchSourceTimer?
        var selfRetention: Unmanaged<TXTQueryContext>?

        func finish() {
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            let result = records
            let cont = continuation
            continuation = nil
            let ref = serviceRef
            serviceRef = nil
            let t = timer
            timer = nil
            let retention = selfRetention
            selfRetention = nil
            lock.unlock()

            t?.cancel()
            if let ref {
                DNSServiceRefDeallocate(ref)
            }
            cont?.resume(returning: result)
            retention?.release()
        }
    }

    private static let txtQueryCallback: DNSServiceQueryRecordReply = { _, flags, _, errorCode, _, _, _, rdlen, rdata, _, rawContext in
        guard let rawContext else { return }
        let box = Unmanaged<TXTQueryContext>.fromOpaque(rawContext).takeUnretainedValue()
        if errorCode == kDNSServiceErr_NoError, let rdata, rdlen > 0 {
            let data = Data(bytes: rdata, count: Int(rdlen))
            let strings = ExitProbes.parseTXTRData(data)
            if !strings.isEmpty {
                box.lock.lock()
                box.records.append(contentsOf: strings)
                box.lock.unlock()
            }
        }
        let moreComing = (flags & kDNSServiceFlagsMoreComing) != 0
        if errorCode != kDNSServiceErr_NoError || !moreComing {
            box.finish()
        }
    }

    private static func queryTXTViaMDNSResponder(name: String, timeoutSeconds: Double) async -> [String] {
        await withCheckedContinuation { continuation in
            let ctx = TXTQueryContext()
            ctx.continuation = continuation
            let queue = DispatchQueue(label: "local.claude-environment-check.dns-txt.\(UUID().uuidString)")
            let unmanaged = Unmanaged.passRetained(ctx)
            ctx.selfRetention = unmanaged

            var ref: DNSServiceRef?
            let status = DNSServiceQueryRecord(
                &ref,
                0,
                0,
                name,
                UInt16(kDNSServiceType_TXT),
                UInt16(kDNSServiceClass_IN),
                ExitProbes.txtQueryCallback,
                unmanaged.toOpaque()
            )

            guard status == kDNSServiceErr_NoError, let createdRef = ref else {
                ctx.finish()
                return
            }

            ctx.lock.lock()
            ctx.serviceRef = createdRef
            ctx.lock.unlock()

            let setStatus = DNSServiceSetDispatchQueue(createdRef, queue)
            guard setStatus == kDNSServiceErr_NoError else {
                ctx.finish()
                return
            }

            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + timeoutSeconds)
            timer.setEventHandler {
                ctx.finish()
            }
            ctx.lock.lock()
            ctx.timer = timer
            ctx.lock.unlock()
            timer.resume()
        }
    }

    static func parseTXTRData(_ data: Data) -> [String] {
        var result: [String] = []
        var offset = 0
        let bytes = [UInt8](data)
        while offset < bytes.count {
            let length = Int(bytes[offset])
            offset += 1
            guard offset + length <= bytes.count else { break }
            let slice = bytes[offset..<(offset + length)]
            if let str = String(bytes: slice, encoding: .utf8), !str.isEmpty {
                result.append(str)
            }
            offset += length
        }
        return result
    }

    private static func queryTXTViaDig(name: String) -> [String] {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/dig")
        process.arguments = ["+short", "+time=3", "+tries=1", "TXT", name]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0, let text = String(data: data, encoding: .utf8) else {
            return []
        }
        var tokens: [String] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "\"").map { $0.trimmingCharacters(in: .whitespaces) }
            for part in parts where !part.isEmpty {
                tokens.append(part)
            }
        }
        return tokens
    }

    static func parseAkamaiWhoami(_ tokens: [String]) -> (ns: String?, ip: String?, ecsSubnet: String?) {
        var ns: String?
        var ip: String?
        var ecs: String?
        var i = 0
        while i < tokens.count {
            let token = tokens[i].trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            let next = (i + 1 < tokens.count)
                ? tokens[i + 1].trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
                : nil
            if token == "ns", let next, isValidIP(next) {
                ns = next
                i += 2
                continue
            } else if token == "ip", let next, isValidIP(next) {
                ip = next
                i += 2
                continue
            } else if token == "ecs", let next, next.contains("/") || isValidIP(next) {
                ecs = next
                i += 2
                continue
            }
            i += 1
        }
        return (ns, ip, ecs)
    }

    private static func parseFirstIP(from tokens: [String]) -> String? {
        for raw in tokens {
            let cleaned = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            if isValidIP(cleaned) { return cleaned }
        }
        return nil
    }

    private static func extractIPFromCIDR(_ cidr: String) -> String? {
        let ip = cidr.split(separator: "/").first.map(String.init) ?? cidr
        return isValidIP(ip) ? ip : nil
    }

    // MARK: - IP Validation Helpers

    static func isIPv4(_ text: String) -> Bool {
        var addr = in_addr()
        return inet_pton(AF_INET, text, &addr) == 1
    }

    static func isIPv6(_ text: String) -> Bool {
        var addr = in6_addr()
        return inet_pton(AF_INET6, text, &addr) == 1
    }

    static func isValidIP(_ text: String) -> Bool {
        isIPv4(text) || isIPv6(text)
    }

    static func isPublicIP(_ text: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            let ip = UInt32(bigEndian: v4.s_addr)
            let a = (ip >> 24) & 0xFF
            let b = (ip >> 16) & 0xFF
            if a == 0 || a == 10 || a == 127 { return false }
            if a == 100 && (b >= 64 && b <= 127) { return false } // CGNAT
            if a == 169 && b == 254 { return false }              // Link-local
            if a == 172 && (b >= 16 && b <= 31) { return false }  // RFC1918
            if a == 192 && b == 168 { return false }              // RFC1918
            if a == 198 && (b == 18 || b == 19) { return false }  // Fake-IP / Benchmark
            if a >= 224 { return false }                          // Multicast/Reserved
            return true
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            let isLoopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
            let isUnspecified = bytes.allSatisfy { $0 == 0 }
            let isULA = (bytes[0] & 0xFE) == 0xFC
            let isLinkLocal = bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80
            let isMulticast = bytes[0] == 0xFF
            return !(isLoopback || isUnspecified || isULA || isLinkLocal || isMulticast)
        }
        return false
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }
}
