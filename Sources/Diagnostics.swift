import CFNetwork
import Darwin
import Foundation

enum ReadingCategory: String, CaseIterable, Identifiable, Sendable {
    case egressCompliance
    case networkLink
    case claudeAudit
    case localEnvironment

    var id: Self { self }

    var title: String {
        switch self {
        case .egressCompliance: "联网与出口合规"
        case .networkLink: "DNS 与代理链路"
        case .claudeAudit: "Claude 客户端与配置审计"
        case .localEnvironment: "本机区域环境"
        }
    }

    var icon: String {
        switch self {
        case .egressCompliance: "globe.asia.australia"
        case .networkLink: "network"
        case .claudeAudit: "terminal"
        case .localEnvironment: "desktopcomputer"
        }
    }
}

enum ReadingID: String, Codable, CaseIterable, Identifiable, Sendable {
    // 联网与出口合规
    case api
    case claudeWeb
    case egressRegion
    case geoConsensus
    case exitQuality
    case ipReputation
    case ipv6Leak
    case exitDrift
    // DNS 与代理链路
    case dnsLeak
    case tunCapture
    case proxy
    case dns
    // Claude 客户端与配置审计
    case claudeCLI
    case claudeProxyConfig
    case configConflicts
    case desktop
    // 本机区域环境
    case timeZone
    case language
    case locale
    case system

    var id: Self { self }

    var category: ReadingCategory {
        switch self {
        case .api, .claudeWeb, .egressRegion, .geoConsensus, .exitQuality, .ipReputation, .ipv6Leak, .exitDrift:
            .egressCompliance
        case .dnsLeak, .tunCapture, .proxy, .dns:
            .networkLink
        case .claudeCLI, .claudeProxyConfig, .configConflicts, .desktop:
            .claudeAudit
        case .timeZone, .language, .locale, .system:
            .localEnvironment
        }
    }

    static func ids(in category: ReadingCategory) -> [ReadingID] {
        allCases.filter { $0.category == category }
    }

    var title: String {
        switch self {
        case .api: "Claude API"
        case .claudeWeb: "Claude Web"
        case .egressRegion: "公网出口与地区合规"
        case .geoConsensus: "多源 GeoIP 交叉核验"
        case .exitQuality: "出口网络属性"
        case .ipReputation: "IP 纯净度与黑名单"
        case .ipv6Leak: "IPv6 双栈防泄漏"
        case .exitDrift: "48h 出口稳定性"
        case .dnsLeak: "真实 DNS 递归出口"
        case .tunCapture: "TUN / Fake-IP 接管"
        case .proxy: "系统全局代理"
        case .dns: "系统 DNS 服务器"
        case .claudeCLI: "Claude Code CLI"
        case .claudeProxyConfig: "Claude Code 代理配置"
        case .configConflicts: "配置覆盖与环境变量冲突"
        case .desktop: "Claude Desktop"
        case .timeZone: "系统时区"
        case .language: "首选语言"
        case .locale: "地区格式"
        case .system: "macOS"
        }
    }

    var source: String {
        switch self {
        case .api: "api.anthropic.com/v1/models · 连通性与延迟"
        case .claudeWeb: "claude.ai · 网页入口可达性"
        case .egressRegion: "Anthropic 185 国支持清单 · 出口归属核验"
        case .geoConsensus: "ipwho.is / ipinfo.io(ip.sb) / Cloudflare Trace"
        case .exitQuality: "统一 ASN 与运营商组织推断（非官方风控）"
        case .ipReputation: "Spamhaus ZEN/DROP · Tor · DroneBL · UCEPROTECT 多源投票"
        case .ipv6Leak: "api4/api6.ipify.org · 双栈绕过检测"
        case .exitDrift: "本机 48 小时采样历史 · 跨国/换 IP 追踪"
        case .dnsLeak: "whoami.ds.akahelp.net + o-o.myaddr.l.google.com · mDNSResponder"
        case .tunCapture: "随机 claude.ai 子域解析 · 198.18.0.0/15 检测"
        case .proxy: "macOS CFNetwork 全局代理设置"
        case .dns: "macOS scutil --dns 解析器列表"
        case .claudeCLI: "常见路径与 PATH 扫描"
        case .claudeProxyConfig: "settings.json 代理、死端口与 NO_PROXY 审计"
        case .configConflicts: "settings.local.json 及 Shell RC 导出扫描"
        case .desktop: "macOS 应用登记与运行状态"
        case .timeZone: "macOS 系统时区 · 与出口时区一致性比对"
        case .language, .locale, .system: "macOS 系统设置"
        }
    }
}

enum ReadingSeverity: String, Codable, Equatable, Sendable {
    case ok
    case caution
    case danger
    case neutral
}

struct Reading: Codable, Equatable, Sendable {
    enum State: String, Codable, Sendable {
        case recorded, response, failed, pending, unavailable
    }

    let value: String
    let state: State
    let severity: ReadingSeverity
    let detail: String?

    init(_ value: String, _ state: State = .recorded, severity: ReadingSeverity = .neutral, detail: String? = nil) {
        self.value = value
        self.state = state
        self.severity = severity
        self.detail = detail
    }

    static let pending = Self("待联网检测", .pending, severity: .neutral)
    static let unavailable = Self("无法读取", .unavailable, severity: .neutral)

    var isComparable: Bool {
        switch state {
        case .recorded, .response, .failed: true
        case .pending, .unavailable: false
        }
    }

    private enum CodingKeys: String, CodingKey {
        case value, state, severity, detail
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        value = try container.decode(String.self, forKey: .value)
        state = try container.decode(State.self, forKey: .state)
        severity = try container.decodeIfPresent(ReadingSeverity.self, forKey: .severity) ?? .neutral
        detail = try container.decodeIfPresent(String.self, forKey: .detail)
    }
}

enum ProbeRoute: Equatable, Sendable {
    case system
    case localProxy(Int)

    var label: String {
        switch self {
        case .system: "系统网络路径"
        case .localProxy(let port): "保护代理 127.0.0.1:\(String(port))"
        }
    }

    var shortBadge: String {
        switch self {
        case .system: "系统直连/TUN"
        case .localProxy(let port): "127.0.0.1:\(String(port))"
        }
    }

    var proxyPort: Int? {
        switch self {
        case .system: nil
        case .localProxy(let port): port
        }
    }
}

struct RecommendedAction: Equatable, Identifiable, Sendable {
    let id: String
    let severity: ReadingSeverity
    let title: String
    let guidance: String
}

struct EnvironmentVerdict: Equatable, Sendable {
    enum Level: Equatable, Sendable {
        case healthy
        case caution
        case risk
        case offlineOnly
    }

    let level: Level
    let headline: String
    let summary: String
    let okCount: Int
    let cautionCount: Int
    let dangerCount: Int
    let pendingCount: Int
    let actions: [RecommendedAction]
}

struct Snapshot: Codable, Sendable {
    let capturedAt: Date
    let online: Bool
    let probeRouteDescription: String
    let observedExitCountry: String?
    let observedExitTimeZone: String?
    let readings: [ReadingID: Reading]

    init(
        capturedAt: Date,
        online: Bool = false,
        probeRouteDescription: String = "系统网络路径",
        observedExitCountry: String? = nil,
        observedExitTimeZone: String? = nil,
        readings: [ReadingID: Reading]
    ) {
        self.capturedAt = capturedAt
        self.online = online
        self.probeRouteDescription = probeRouteDescription
        self.observedExitCountry = observedExitCountry
        self.observedExitTimeZone = observedExitTimeZone
        self.readings = readings
    }

    private enum CodingKeys: String, CodingKey {
        case capturedAt, online, probeRouteDescription, observedExitCountry, observedExitTimeZone, readings
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        capturedAt = try container.decode(Date.self, forKey: .capturedAt)
        online = try container.decodeIfPresent(Bool.self, forKey: .online) ?? false
        probeRouteDescription = try container.decodeIfPresent(String.self, forKey: .probeRouteDescription) ?? "系统网络路径"
        observedExitCountry = try container.decodeIfPresent(String.self, forKey: .observedExitCountry)
        observedExitTimeZone = try container.decodeIfPresent(String.self, forKey: .observedExitTimeZone)
        readings = try container.decode([ReadingID: Reading].self, forKey: .readings)
    }

    func reading(_ id: ReadingID) -> Reading {
        readings[id] ?? .unavailable
    }

    var verdict: EnvironmentVerdict {
        Diagnostics.evaluateVerdict(for: self)
    }

    func markdownReport() -> String {
        let verdict = self.verdict
        var lines: [String] = []
        lines.append("# Claude 环境体检报告 (v1.2.0)")
        lines.append("")
        lines.append("- 采样时间：\(capturedAt.formatted(date: .numeric, time: .standard))")
        lines.append("- 检测模式：\(online ? "联网实测" : "仅本机检查")（\(probeRouteDescription)）")
        lines.append("- 综合结论：**\(verdict.headline)** — \(verdict.summary)")
        lines.append("")
        if !verdict.actions.isEmpty {
            lines.append("## 建议处理项")
            for action in verdict.actions {
                let tag = action.severity == .danger ? "[高风险]" : "[注意]"
                lines.append("- \(tag) **\(action.title)**：\(action.guidance)")
            }
            lines.append("")
        }
        for category in ReadingCategory.allCases {
            lines.append("## \(category.title)")
            for id in ReadingID.ids(in: category) {
                let r = reading(id)
                let icon: String
                switch r.severity {
                case .ok: icon = "🟢"
                case .caution: icon = "🟡"
                case .danger: icon = "🔴"
                case .neutral: icon = r.state == .pending ? "⏳" : "⚪"
                }
                let compactValue = r.value.replacingOccurrences(of: "\n", with: " / ")
                if let detail = r.detail, !detail.isEmpty {
                    lines.append("- \(icon) **\(id.title)**：`\(compactValue)`（\(detail)）")
                } else {
                    lines.append("- \(icon) **\(id.title)**：`\(compactValue)`")
                }
            }
            lines.append("")
        }
        lines.append("> 说明：报告已自动脱敏，不包含任何 API Key、Cookie 或账号凭证。")
        return lines.joined(separator: "\n")
    }
}

enum Comparison: Equatable {
    case changed, same, incomplete

    init(_ before: Reading, _ after: Reading) {
        if !before.isComparable || !after.isComparable {
            self = .incomplete
        } else {
            self = (before.value == after.value && before.severity == after.severity) ? .same : .changed
        }
    }
}

enum Diagnostics {
    private static let apiURL = URL(string: "https://api.anthropic.com/v1/models")!
    private static let claudeWebURL = URL(string: "https://claude.ai/")!

    @MainActor
    static func capture(online: Bool, route: ProbeRoute = .system, historyStore: ExitHistoryStore = .shared) async -> Snapshot {
        let capturedAt = Date()
        let proxyPort = route.proxyPort

        let localNetworkTask = Task.detached(priority: .userInitiated) {
            (readProxy(), readDNS())
        }
        async let auditTask = ClaudeCodeAudit.inspect()

        async let apiTask = online ? probeAPI(proxyPort: proxyPort) : .pending
        async let webTask = online ? probeClaudeWeb(proxyPort: proxyPort) : .pending
        async let geoTask: MultiSourceGeoReport? = online ? ExitProbes.probeMultiSourceGeo(proxyPort: proxyPort) : nil
        async let dualStackTask: DualStackReport? = online ? ExitProbes.probeDualStack(proxyPort: proxyPort) : nil
        async let dnsProbeTask: DNSProbeReport? = online ? ExitProbes.probeDNSLeak(proxyPort: proxyPort) : nil
        async let existingHistoryTask = historyStore.summary(now: capturedAt)

        let (proxy, dns) = await localNetworkTask.value
        let audit = await auditTask
        let apiReading = await apiTask
        let webReading = await webTask
        let geoReport = await geoTask
        let dualStackReport = await dualStackTask
        let dnsProbeReport = await dnsProbeTask
        let reputationReport: IPReputationReport? = if online, let ip = geoReport?.primaryIP {
            await IPReputationProber.probe(ip: ip, geo: geoReport)
        } else {
            nil
        }

        // Update 48h exit history when online scan observed a valid IP
        let driftSummary: ExitDriftSummary
        if let geoReport, let ip = geoReport.primaryIP {
            let sample = ExitSample(
                capturedAt: capturedAt,
                ip: ip,
                countryCode: geoReport.primaryCountryCode,
                asn: geoReport.networkASN,
                org: geoReport.networkOrg,
                networkKind: geoReport.networkKind,
                probePath: route.label
            )
            driftSummary = await historyStore.record(sample)
        } else {
            driftSummary = await existingHistoryTask
        }

        let timeZone = TimeZone.autoupdatingCurrent
        let offsetMinutes = timeZone.secondsFromGMT(for: capturedAt) / 60
        let absoluteMinutes = abs(offsetMinutes)
        let offsetStr = String(format: "%@%02d:%02d", offsetMinutes < 0 ? "−" : "+",
                               absoluteMinutes / 60, absoluteMinutes % 60)
        let language = Locale.preferredLanguages.joined(separator: " · ")
        let version = ProcessInfo.processInfo.operatingSystemVersion

        let readings: [ReadingID: Reading] = [
            .api: apiReading,
            .claudeWeb: webReading,
            .egressRegion: buildEgressRegionReading(geo: geoReport),
            .geoConsensus: buildGeoConsensusReading(geo: geoReport),
            .exitQuality: buildExitQualityReading(geo: geoReport),
            .ipReputation: buildIPReputationReading(report: reputationReport, online: online),
            .ipv6Leak: buildIPv6Reading(dualStack: dualStackReport, geo: geoReport),
            .exitDrift: buildExitDriftReading(summary: driftSummary),
            .dnsLeak: buildDNSLeakReading(probe: dnsProbeReport, geo: geoReport, route: route),
            .tunCapture: buildTUNCaptureReading(probe: dnsProbeReport, online: online),
            .proxy: proxy,
            .dns: dns,
            .claudeCLI: buildClaudeCLIReading(audit: audit),
            .claudeProxyConfig: buildClaudeProxyConfigReading(audit: audit),
            .configConflicts: buildConfigConflictsReading(audit: audit),
            .desktop: buildDesktopReading(audit: audit),
            .timeZone: buildTimeZoneReading(
                localTZ: timeZone,
                offsetLabel: offsetStr,
                exitTZID: geoReport?.primaryTimeZone,
                processTZ: audit.processTZ,
                capturedAt: capturedAt
            ),
            .language: language.isEmpty ? .unavailable : Reading(language, .recorded, severity: .neutral),
            .locale: Reading(Locale.autoupdatingCurrent.identifier, .recorded, severity: .neutral),
            .system: Reading("macOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)", .recorded, severity: .neutral),
        ]

        return Snapshot(
            capturedAt: capturedAt,
            online: online,
            probeRouteDescription: route.label,
            observedExitCountry: geoReport?.primaryCountryCode,
            observedExitTimeZone: geoReport?.primaryTimeZone,
            readings: readings
        )
    }

    // MARK: - Reading Builders

    private static func buildEgressRegionReading(geo: MultiSourceGeoReport?) -> Reading {
        guard let geo else { return .pending }
        guard let ip = geo.primaryIP else {
            return Reading("未能获取公网出口 IP", .failed, severity: .danger, detail: "3 家 GeoIP 源均未返回有效结果，请检查网络连接或代理可用性")
        }
        let code = geo.primaryCountryCode
        let support = ClaudeRegions.support(for: code)
        let regionName = ClaudeRegions.displayName(for: code)
        let locationParts = [geo.primary?.regionName, geo.primary?.city].compactMap { $0 }.filter { !$0.isEmpty }
        var detailParts: [String] = []
        if !locationParts.isEmpty { detailParts.append(locationParts.joined(separator: " · ")) }
        if let colo = geo.cloudflareColo, !colo.isEmpty { detailParts.append("CF 边缘 \(colo)") }
        if let warp = geo.cloudflareWarp, warp != "off" { detailParts.append("WARP \(warp)") }

        switch support {
        case .supported:
            detailParts.append("位于 Anthropic 官方支持地区（185 国清单）")
            return Reading("\(ip) · \(regionName)", .response, severity: .ok, detail: detailParts.joined(separator: " · "))
        case .unsupported:
            detailParts.append("不在 Anthropic 官方支持清单内，直接使用存在高封号/拒访风险")
            return Reading("\(ip) · \(regionName)（不支持）", .response, severity: .danger, detail: detailParts.joined(separator: " · "))
        case .unknown:
            detailParts.append("未能识别归属国家代码，无法确认是否受支持")
            return Reading("\(ip) · 地区未知", .response, severity: .caution, detail: detailParts.joined(separator: " · "))
        }
    }

    private static func buildGeoConsensusReading(geo: MultiSourceGeoReport?) -> Reading {
        guard let geo else { return .pending }
        let summaryList = geo.sources.map { src in
            if let code = src.countryCode {
                return "\(src.source): \(code)"
            }
            return "\(src.source): 失败"
        }.joined(separator: " · ")

        switch geo.consensus {
        case let .consistent(code, agreeingCount, total):
            let support = ClaudeRegions.support(for: code)
            let sev: ReadingSeverity = support == .supported ? .ok : (support == .unsupported ? .danger : .caution)
            return Reading("\(agreeingCount)/\(total) 源一致 · \(ClaudeRegions.displayName(for: code))",
                           .response, severity: sev, detail: summaryList)
        case let .split(countries, _):
            return Reading("出口国家分流冲突 · \(countries.joined(separator: " / "))",
                           .response, severity: .danger,
                           detail: "不同站点看到不同国家出口（\(summaryList)），说明代理分流规则不一致")
        case let .singleSource(code, source):
            return Reading("仅 1 源返回 · \(ClaudeRegions.displayName(for: code))",
                           .response, severity: .caution,
                           detail: "仅 \(source) 成功，暂不足以交叉核验（\(summaryList)）")
        case .unavailable:
            return Reading("多源查询均失败", .failed, severity: .danger, detail: summaryList)
        }
    }

    private static func buildExitQualityReading(geo: MultiSourceGeoReport?) -> Reading {
        guard let geo else { return .pending }
        guard geo.primaryIP != nil else {
            return Reading("无出口信息", .unavailable, severity: .neutral)
        }
        let asnText = geo.networkASN.map { "AS\($0)" }
        let orgText = geo.networkOrg
        let meta = [asnText, orgText].compactMap { $0 }.joined(separator: " · ")

        switch geo.networkKind {
        case .residential:
            return Reading(geo.networkKind.label, .response, severity: .ok,
                           detail: meta.isEmpty ? "运营商特征倾向住宅/宽带线路" : meta)
        case .hosting:
            return Reading(geo.networkKind.label, .response, severity: .caution,
                           detail: (meta.isEmpty ? "识别为云厂商或机房段" : meta) + " · 部分云/机房段更容易触发风控验证")
        case .unknown:
            return Reading(geo.networkKind.label, .response, severity: .neutral,
                           detail: meta.isEmpty ? "GeoIP 源未返回 ASN/组织信息" : "\(meta) · 不猜测住宅或机房")
        }
    }

    static func buildIPReputationReading(report: IPReputationReport?, online: Bool) -> Reading {
        guard online else { return .pending }
        guard let report else {
            return Reading("无 IPv4 出口可检", .unavailable, severity: .neutral,
                           detail: "联网测得 IPv4 出口后将自动进行多源黑名单与 Tor 库交叉投票")
        }
        return Reading(report.headline, .response, severity: report.severity, detail: report.detail)
    }

    private static func buildIPv6Reading(dualStack: DualStackReport?, geo: MultiSourceGeoReport?) -> Reading {
        guard let dualStack else { return .pending }
        guard let ipv6 = dualStack.ipv6 else {
            return Reading("未暴露公网 IPv6", .response, severity: .ok,
                           detail: "当前探测路径无 IPv6 公网直出，不存在 IPv6 绕过代理泄漏风险")
        }
        let v6Code = dualStack.ipv6Geo?.countryCode
        let v4Code = geo?.primaryCountryCode
        let v6Region = ClaudeRegions.displayName(for: v6Code)
        let support = ClaudeRegions.support(for: v6Code)

        if support == .unsupported {
            return Reading("\(ipv6) · \(v6Region)（不支持地区）", .response, severity: .danger,
                           detail: "IPv6 出口落在不支持地区，访问双栈域名时极易绕过 IPv4 代理直接暴露真实位置")
        }
        if let v4Code, let v6Code, v4Code != v6Code {
            return Reading("\(ipv6) · \(v6Region) ≠ IPv4(\(v4Code))", .response, severity: .caution,
                           detail: "IPv6 与 IPv4 出口国家不一致，双栈请求可能触发跨国异常")
        }
        if support == .supported {
            return Reading("\(ipv6) · \(v6Region)", .response, severity: .ok,
                           detail: "IPv6 与主出口一致且位于 Anthropic 支持地区")
        }
        return Reading("\(ipv6) · 归属待确认", .response, severity: .caution,
                       detail: "检测到公网 IPv6 出口，但未能查得其归属国家")
    }

    static func buildExitDriftReading(summary: ExitDriftSummary) -> Reading {
        guard summary.sampleCount > 0 else {
            return Reading("暂无 48h 联网采样记录", .pending, severity: .neutral,
                           detail: "执行联网检测后将自动记录出口 IP 与归属国变化")
        }
        let countryList = summary.countries.joined(separator: " → ")
        if summary.countryChanges >= 2 || summary.guardedCountryChanges > 0 {
            let reason = summary.guardedCountryChanges > 0
                ? "守卫/代理路径下发生 \(summary.guardedCountryChanges) 次跨国漂移（地区：\(countryList)），请锁定单一固定节点"
                : "48h 内共采样 \(summary.sampleCount) 次，涉及地区：\(countryList)。频繁跨国切换是高危风控信号"
            return Reading("跨国跳变 \(summary.countryChanges) 次 · \(summary.uniqueIPCount) 个 IP",
                           .recorded, severity: .danger,
                           detail: reason)
        }
        if summary.countryChanges == 1 {
            return Reading("历史记录有 1 次跨国切换 · \(summary.uniqueIPCount) 个 IP",
                           .recorded, severity: .caution,
                           detail: "48h 内涉及地区：\(countryList)（若是开启代理或换固定节点前的旧采样，点「确认已固定，清空 48h 记录」即可重置）")
        }
        if summary.ipChanges > 0 {
            return Reading("同地区换 IP \(summary.ipChanges) 次 · \(summary.uniqueIPCount) 个 IP",
                           .recorded, severity: .caution,
                           detail: "48h 内共采样 \(summary.sampleCount) 次（地区：\(countryList.isEmpty ? "未知" : countryList)），建议为 Claude 固定单一节点")
        }
        return Reading("出口稳定 · 无漂移", .recorded, severity: .ok,
                       detail: "48h 内共采样 \(summary.sampleCount) 次，始终保持单一出口（\(countryList.isEmpty ? "未知" : countryList)）")
    }

    private static func buildDNSLeakReading(probe: DNSProbeReport?, geo: MultiSourceGeoReport?, route: ProbeRoute) -> Reading {
        guard let probe else { return .pending }
        guard let resolverIP = probe.recursiveResolverIP else {
            return Reading("未能测得递归 DNS 出口", .failed, severity: .caution,
                           detail: "系统解析器对 whoami.ds.akahelp.net / o-o.myaddr.l.google.com 均未返回 TXT 记录")
        }
        let dnsCode = probe.resolverGeo?.countryCode
        let dnsSupport = ClaudeRegions.support(for: dnsCode)
        let dnsRegion = ClaudeRegions.displayName(for: dnsCode)
        let dnsASN = probe.resolverGeo?.asn
        let dnsOrg = probe.resolverGeo?.org
        let fakeIPActive = probe.fakeIPAddress.map(ExitProbes.isFakeIP) == true

        let ecsCode = probe.ecsGeo?.countryCode
        let ecsUnsupported = probe.ecsSubnet != nil && ClaudeRegions.support(for: ecsCode) == .unsupported

        var detailParts: [String] = []
        if let src = probe.probeSource { detailParts.append("探测源 \(src)") }
        if let dnsASN { detailParts.append("AS\(dnsASN)") }
        if let dnsOrg { detailParts.append(dnsOrg) }
        if let ecs = probe.ecsSubnet {
            let ecsTag = ecsCode.map { " (\($0))" } ?? ""
            detailParts.append("ECS 子网 \(ecs)\(ecsTag)")
        }

        let isProxyOnlyNoTUN = (route.proxyPort != nil && !fakeIPActive)

        if dnsSupport == .unsupported || ecsUnsupported {
            if isProxyOnlyNoTUN {
                detailParts.append("仅影响未走 HTTP_PROXY 的系统直连流量；Claude Code 经 HTTP CONNECT 由代理远程解析")
                return Reading("\(resolverIP) · \(dnsRegion)（系统直连 DNS）", .response, severity: .caution,
                               detail: detailParts.joined(separator: " · "))
            } else {
                detailParts.append(ecsUnsupported ? "检测到 EDNS Client Subnet 暴露国内网段" : "递归 DNS 位于不支持地区，存在 DNS 泄漏风险")
                return Reading("\(resolverIP) · \(dnsRegion)（疑似泄漏）", .response, severity: .danger,
                               detail: detailParts.joined(separator: " · "))
            }
        }

        if let exitCode = geo?.primaryCountryCode, let dnsCode, exitCode != dnsCode {
            if let dnsASN, ExitClassifier.anycastDNSASNs.contains(dnsASN) {
                detailParts.append("公共 Anycast 解析器（经支持地区出口）")
                return Reading("\(resolverIP) · \(dnsRegion)", .response, severity: .ok,
                               detail: detailParts.joined(separator: " · "))
            }
            detailParts.append("DNS 归属 \(dnsCode) 与主出口 \(exitCode) 不同，建议保持同地区解析")
            return Reading("\(resolverIP) · \(dnsRegion)（跨区解析）", .response, severity: .caution,
                           detail: detailParts.joined(separator: " · "))
        }

        if dnsSupport == .supported {
            detailParts.append("DNS 递归出口位于支持地区，未发现不支持地区泄漏")
            return Reading("\(resolverIP) · \(dnsRegion)", .response, severity: .ok,
                           detail: detailParts.joined(separator: " · "))
        }

        return Reading("\(resolverIP) · 归属未知", .response, severity: .neutral,
                       detail: detailParts.joined(separator: " · "))
    }

    private static func buildTUNCaptureReading(probe: DNSProbeReport?, online: Bool) -> Reading {
        guard online, let probe else { return .pending }
        guard let ip = probe.fakeIPAddress else {
            return Reading("未检测到 Fake-IP TUN", .response, severity: .neutral,
                           detail: "随机子域未返回 Fake-IP（常规系统代理或仅代理 Claude Code 模式下属正常）")
        }
        if ExitProbes.isFakeIP(ip) {
            return Reading("已接管 · Fake-IP \(ip)", .response, severity: .ok,
                           detail: "claude.ai 随机子域命中 198.18.0.0/15，系统级 TUN 透明接管生效中")
        }
        return Reading("常规解析 · \(ip)", .response, severity: .neutral,
                       detail: "未走 Fake-IP 隧道，请确认浏览器与 Claude Desktop 是否已走系统代理")
    }

    private static func buildClaudeCLIReading(audit: ClaudeCodeAuditReport) -> Reading {
        guard let path = audit.cliPath else {
            return Reading("未检测到 claude 命令", .recorded, severity: .neutral,
                           detail: "未在常见目录（Homebrew / ~/.local/bin / PATH）中找到 Claude Code CLI")
        }
        let ver = audit.cliVersion ?? "版本未知"
        return Reading("已安装 · \(ver)", .recorded, severity: .ok, detail: path)
    }

    private static func buildClaudeProxyConfigReading(audit: ClaudeCodeAuditReport) -> Reading {
        if audit.settingsParseError {
            return Reading("settings.json 格式损坏", .failed, severity: .danger,
                           detail: "\(audit.configDirectory)/settings.json 不是合法 JSON，Claude Code 可能无法读取代理")
        }
        if !audit.deadLocalPorts.isEmpty {
            let ports = audit.deadLocalPorts.map(String.init).joined(separator: ", ")
            return Reading("检测到死代理端口：127.0.0.1:\(ports)", .recorded, severity: .danger,
                           detail: "settings.json 指向的本机端口当前未监听，Claude Code 请求会直接失败（请启动 Clash 或恢复设置）")
        }
        if !audit.dangerousNoProxy.isEmpty {
            let tokens = audit.dangerousNoProxy.joined(separator: ", ")
            return Reading("NO_PROXY 误放行风险：\(tokens)", .recorded, severity: .danger,
                           detail: "settings.json 的 NO_PROXY 会导致 Anthropic/Claude 域名绕过代理直连")
        }
        if audit.proxyMismatch {
            let pairs = audit.configuredProxies.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " · ")
            return Reading("代理键指向不一致", .recorded, severity: .caution, detail: pairs)
        }
        if let sample = audit.configuredProxies["HTTPS_PROXY"] ?? audit.configuredProxies["https_proxy"] ?? audit.configuredProxies.values.first {
            var extras: [String] = ["共 \(audit.configuredProxies.count) 个代理键（\(audit.configDirectory)/settings.json）"]
            if let tz = audit.processTZ { extras.append("进程 TZ=\(tz)") }
            if let lang = audit.processLang { extras.append("LANG=\(lang)") }
            if audit.customBaseURLPresent { extras.append("含自定义 ANTHROPIC_BASE_URL") }
            return Reading("已配置 · \(sample)", .recorded, severity: .ok,
                           detail: extras.joined(separator: " · "))
        }
        let extra = audit.customBaseURLPresent ? "已配置自定义 ANTHROPIC_BASE_URL，未配置代理" : "未在 settings.json 中配置代理，依赖系统 TUN 或 Shell 环境"
        return Reading("未配置独立代理", .recorded, severity: .neutral, detail: extra)
    }

    private static func buildConfigConflictsReading(audit: ClaudeCodeAuditReport) -> Reading {
        var issues: [String] = []
        if !audit.localSettingsOverrides.isEmpty {
            issues.append("settings.local.json 覆盖：\(audit.localSettingsOverrides.joined(separator: ", "))")
        }
        if !audit.shellOverrides.isEmpty {
            let preview = audit.shellOverrides.prefix(4).map { "\($0.file):\($0.line) (\($0.key))" }.joined(separator: "、")
            let suffix = audit.shellOverrides.count > 4 ? " 等 \(audit.shellOverrides.count) 处" : ""
            issues.append("Shell 启动文件导出：\(preview)\(suffix)")
        }
        if !audit.processEnvOverrides.isEmpty {
            issues.append("当前进程继承：\(audit.processEnvOverrides.joined(separator: ", "))")
        }
        if issues.isEmpty {
            return Reading("未发现覆盖冲突", .recorded, severity: .ok,
                           detail: "settings.local.json 及 ~/.zshrc 等启动文件未导出冲突的代理或 BaseURL")
        }
        let hasHighRisk = !audit.localSettingsOverrides.isEmpty
        return Reading("发现 \(issues.count) 类潜在覆盖项", .recorded, severity: hasHighRisk ? .caution : .caution,
                       detail: issues.joined(separator: "；"))
    }

    private static func buildDesktopReading(audit: ClaudeCodeAuditReport) -> Reading {
        guard audit.desktopFound else {
            return Reading("未安装", .recorded, severity: .neutral, detail: "macOS 应用登记中未找到 com.anthropic.claudefordesktop")
        }
        let ver = audit.desktopVersion ?? "版本未知"
        let runState = audit.desktopRunning ? "运行中" : "未运行"
        return Reading("已安装 · \(ver)（\(runState)）", .recorded, severity: .neutral,
                       detail: audit.desktopRunning ? "注意：Claude Desktop 不读取 ~/.claude/settings.json，依赖系统代理或 TUN" : "macOS 应用登记信息")
    }

    static func buildTimeZoneReading(
        localTZ: TimeZone, offsetLabel: String, exitTZID: String?, processTZ: String?, capturedAt: Date
    ) -> Reading {
        let baseValue = "\(localTZ.identifier) · UTC\(offsetLabel)"
        guard let exitTZID, let exitTZ = TimeZone(identifier: exitTZID) else {
            if let processTZ, !processTZ.isEmpty {
                return Reading("\(baseValue) · 进程 TZ=\(processTZ)", .recorded, severity: .ok,
                               detail: "Claude Code 已配置进程级 TZ=\(processTZ)（未改动系统时区）")
            }
            return Reading(baseValue, .recorded, severity: .neutral, detail: "联网检测后可与出口时区自动比对")
        }
        let exitOffset = exitTZ.secondsFromGMT(for: capturedAt)
        // If Claude Code process-level TZ is already configured and aligns with the exit timezone, mark compliant!
        if let processTZ, let procTZObj = TimeZone(identifier: processTZ) {
            let procOffset = procTZObj.secondsFromGMT(for: capturedAt)
            if procTZObj.identifier == exitTZ.identifier || procOffset == exitOffset {
                return Reading("\(localTZ.identifier) · 进程已对齐 \(processTZ)", .recorded, severity: .ok,
                               detail: "Claude Code 已启用进程级 TZ=\(processTZ)（与出口 \(exitTZID) 一致，未改动 macOS 全局时区）")
            }
        }
        let localOffset = localTZ.secondsFromGMT(for: capturedAt)
        if localTZ.identifier == exitTZ.identifier {
            return Reading(baseValue, .recorded, severity: .ok, detail: "与公网出口时区完全一致")
        }
        if localOffset == exitOffset {
            // Zero false positives for Singapore / Taiwan / Perth (UTC+8)!
            return Reading(baseValue, .recorded, severity: .ok,
                           detail: "UTC 偏移与出口 \(exitTZID) 一致（0 小时差，不会误报 UTC+8 风险）")
        }
        let diffHours = Double(localOffset - exitOffset) / 3600.0
        let diffText = diffHours.truncatingRemainder(dividingBy: 1) == 0
            ? "\(Int(abs(diffHours))) 小时"
            : String(format: "%.1f 小时", abs(diffHours))
        return Reading(baseValue, .recorded, severity: .caution,
                       detail: "与出口时区 \(exitTZID) 相差 \(diffText)（勾选下方「进程级对齐 TZ/LANG」启动守卫即可无侵入对齐）")
    }

    // MARK: - Overall Verdict Synthesizer

    static func evaluateVerdict(for snapshot: Snapshot) -> EnvironmentVerdict {
        var okCount = 0
        var cautionCount = 0
        var dangerCount = 0
        var pendingCount = 0
        var actions: [RecommendedAction] = []

        for id in ReadingID.allCases {
            let r = snapshot.reading(id)
            if r.state == .pending {
                pendingCount += 1
                continue
            }
            switch r.severity {
            case .ok: okCount += 1
            case .caution: cautionCount += 1
            case .danger: dangerCount += 1
            case .neutral: break
            }
        }

        // Prioritized, concrete actionable recommendations (only for real observed issues)
        let egress = snapshot.reading(.egressRegion)
        if egress.severity == .danger {
            actions.append(.init(
                id: "egress-region",
                severity: .danger,
                title: "切换至 Anthropic 官方支持地区节点",
                guidance: "当前出口不在 185 国支持清单内（或查询失败），请在 Clash Verge 切至美/日/新/台/英/德/加等支持地区节点，切勿使用香港/内地/俄罗斯节点。"
            ))
        }
        let consensus = snapshot.reading(.geoConsensus)
        if consensus.severity == .danger {
            actions.append(.init(
                id: "geo-split",
                severity: .danger,
                title: "修复多源出口国家分流冲突",
                guidance: "不同 GeoIP 站点看到了不同国家出口，请检查 Clash 分流规则，确保 Anthropic / Cloudflare / 常见探测域名统一走同一固定节点。"
            ))
        }
        let rep = snapshot.reading(.ipReputation)
        if rep.severity == .danger {
            actions.append(.init(
                id: "ip-reputation",
                severity: .danger,
                title: "更换命中权威黑名单 / Tor 库的节点",
                guidance: rep.detail ?? "当前出口 IP 被多个权威黑名单或 Tor 出口库标记，建议更换更纯净的固定节点。"
            ))
        }
        let ipv6 = snapshot.reading(.ipv6Leak)
        if ipv6.severity == .danger {
            actions.append(.init(
                id: "ipv6-leak",
                severity: .danger,
                title: "封堵 IPv6 直连泄漏",
                guidance: "检测到公网 IPv6 落在不支持地区。请在 Clash Verge 中关闭或代理 IPv6，或在系统网络设置将 IPv6 改为「仅本地链路」。"
            ))
        }
        let dnsLeak = snapshot.reading(.dnsLeak)
        if dnsLeak.severity == .danger {
            actions.append(.init(
                id: "dns-leak",
                severity: .danger,
                title: "修复 DNS 递归出口泄漏",
                guidance: "递归 DNS 出口或 ECS 网段落在不支持地区。建议在 Clash 开启 Fake-IP + 代理远端 DNS（DoH 走代理节点），避免本机 ISP 递归解析 Claude 域名。"
            ))
        }
        let claudeProxy = snapshot.reading(.claudeProxyConfig)
        if claudeProxy.severity == .danger {
            actions.append(.init(
                id: "claude-proxy-broken",
                severity: .danger,
                title: "修复 Claude Code 代理配置故障",
                guidance: claudeProxy.detail ?? "请检查 ~/.claude/settings.json 中的端口是否存活及 NO_PROXY 是否误排除 anthropic.com。"
            ))
        }
        let api = snapshot.reading(.api)
        if api.severity == .danger {
            actions.append(.init(
                id: "api-unreachable",
                severity: .danger,
                title: "排查 Claude API 连接失败",
                guidance: "无法正常收到 api.anthropic.com 响应（\(api.value)）。请先点击「测试代理」确认节点联通性。"
            ))
        }
        let drift = snapshot.reading(.exitDrift)
        if drift.severity == .danger {
            actions.append(.init(
                id: "exit-drift",
                severity: .danger,
                title: "停止跨国节点漂移",
                guidance: drift.detail ?? "检测到多次或守卫期间跨国出口跳变，请将 Claude 规则绑定到 Clash 的手动固定组（select）。"
            ))
        } else if drift.severity == .caution {
            actions.append(.init(
                id: "exit-drift",
                severity: .caution,
                title: "48h 历史存在出口切换记录",
                guidance: drift.detail ?? "若当前节点已经固定，可直接点右侧按钮清空旧的 48h 切换记录。"
            ))
        }
        let exitQuality = snapshot.reading(.exitQuality)
        if exitQuality.severity == .caution {
            actions.append(.init(
                id: "hosting-exit",
                severity: .caution,
                title: "留意云机房出口风控风险",
                guidance: "当前出口 ASN 属于云厂商/数据中心（\(exitQuality.detail ?? "")），若遇到登录验证或 403，优先更换住宅/ISP 质量更高的节点。"
            ))
        }
        let conflicts = snapshot.reading(.configConflicts)
        if conflicts.severity == .caution {
            actions.append(.init(
                id: "config-conflicts",
                severity: .caution,
                title: "核对 Shell / 本地配置覆盖",
                guidance: conflicts.detail ?? "存在可能覆盖 ~/.claude/settings.json 的环境变量导出，请核对生效顺序。"
            ))
        }
        let tz = snapshot.reading(.timeZone)
        if tz.severity == .caution {
            actions.append(.init(
                id: "timezone-diff",
                severity: .caution,
                title: "时区与出口存在时差（按需处理）",
                guidance: tz.detail ?? "浏览器访问 claude.ai 时建议保持时区一致；Claude Code CLI 可通过环境变量 TZ 单独对齐而无需改全局系统时区。"
            ))
        }

        if !snapshot.online {
            if dangerCount > 0 {
                return EnvironmentVerdict(
                    level: .risk,
                    headline: "本机配置发现 \(dangerCount) 项高风险问题",
                    summary: "尚未执行联网实测；建议先修复本机配置告警，再点击「联网检测」核验公网出口与 DNS。",
                    okCount: okCount, cautionCount: cautionCount, dangerCount: dangerCount, pendingCount: pendingCount,
                    actions: actions
                )
            }
            return EnvironmentVerdict(
                level: .offlineOnly,
                headline: "本机配置已读取，等待联网实测",
                summary: cautionCount > 0
                    ? "发现 \(cautionCount) 项本机配置提示；点击右上角「联网检测」验证出口国家、IPv6 与真实 DNS 出口。"
                    : "本机代理与 Claude 配置未见异常；点击右上角「联网检测」执行全链路出口体检。",
                okCount: okCount, cautionCount: cautionCount, dangerCount: dangerCount, pendingCount: pendingCount,
                actions: actions
            )
        }

        if dangerCount > 0 {
            return EnvironmentVerdict(
                level: .risk,
                headline: "发现 \(dangerCount) 项高风险问题，暂不建议直接登录 Claude",
                summary: "通过 \(okCount) 项 · 高风险 \(dangerCount) 项 · 注意 \(cautionCount) 项（路径：\(snapshot.probeRouteDescription)）",
                okCount: okCount, cautionCount: cautionCount, dangerCount: dangerCount, pendingCount: pendingCount,
                actions: actions
            )
        }
        if cautionCount > 0 {
            return EnvironmentVerdict(
                level: .caution,
                headline: "出口核心合规，但有 \(cautionCount) 项建议关注",
                summary: "通过 \(okCount) 项 · 无高危阻断 · 注意 \(cautionCount) 项（路径：\(snapshot.probeRouteDescription)）",
                okCount: okCount, cautionCount: cautionCount, dangerCount: dangerCount, pendingCount: pendingCount,
                actions: actions
            )
        }
        return EnvironmentVerdict(
            level: .healthy,
            headline: "环境合规，各项实测均已通过",
            summary: "通过 \(okCount) 项 · 零高危 · 零告警（路径：\(snapshot.probeRouteDescription)）",
            okCount: okCount, cautionCount: cautionCount, dangerCount: dangerCount, pendingCount: pendingCount,
            actions: actions
        )
    }

    // MARK: - Local Network Readers

    private static func readProxy() -> Reading {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return .unavailable
        }
        let protocols = [
            ("HTTP", kCFNetworkProxiesHTTPEnable, kCFNetworkProxiesHTTPProxy, kCFNetworkProxiesHTTPPort),
            ("HTTPS", kCFNetworkProxiesHTTPSEnable, kCFNetworkProxiesHTTPSProxy, kCFNetworkProxiesHTTPSPort),
            ("SOCKS", kCFNetworkProxiesSOCKSEnable, kCFNetworkProxiesSOCKSProxy, kCFNetworkProxiesSOCKSPort)
        ]
        var entries: [String] = []
        for (name, enable, address, port) in protocols where enabled(settings, enable) {
            guard let host = settings[address as String] as? String, !host.isEmpty,
                  let number = settings[port as String] as? Int else {
                entries.append("\(name) · 地址或端口缺失")
                continue
            }
            let formattedHost = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
            entries.append("\(name) · \(formattedHost):\(number)")
        }
        if enabled(settings, kCFNetworkProxiesProxyAutoConfigEnable) {
            entries.append("PAC 自动配置已启用")
        }
        if enabled(settings, kCFNetworkProxiesProxyAutoDiscoveryEnable) {
            entries.append("代理自动发现已启用")
        }
        return Reading(entries.isEmpty ? "未启用全局代理配置" : entries.joined(separator: "\n"), .recorded, severity: .neutral)
    }

    private static func enabled(_ settings: [String: Any], _ key: CFString) -> Bool {
        (settings[key as String] as? NSNumber)?.boolValue == true
    }

    private static func readDNS() -> Reading {
        let command = Process()
        let output = Pipe()
        command.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        command.arguments = ["--dns"]
        command.standardOutput = output
        command.standardError = FileHandle.nullDevice

        do {
            try command.run()
        } catch {
            return .unavailable
        }
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        command.waitUntilExit()
        guard command.terminationStatus == 0, let text = String(data: bytes, encoding: .utf8) else {
            return .unavailable
        }

        let addresses = parseResolverAddresses(text)
        return Reading(addresses.isEmpty ? "系统未列出 DNS 服务器" : addresses.joined(separator: " · "),
                       .recorded, severity: .neutral)
    }

    static func parseResolverAddresses(_ text: String) -> [String] {
        var addresses: [String] = []
        var seen: Set<String> = []
        for line in text.split(whereSeparator: \.isNewline) {
            let entry = line.trimmingCharacters(in: .whitespaces)
            guard entry.hasPrefix("nameserver["), let separator = entry.firstIndex(of: ":") else {
                continue
            }
            let address = entry[entry.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            if !address.isEmpty, seen.insert(address).inserted {
                addresses.append(address)
            }
        }
        return addresses
    }

    // MARK: - Online Endpoint Probes

    private static func probeAPI(proxyPort: Int?) async -> Reading {
        let started = ContinuousClock.now
        do {
            let (_, response) = try await httpRequest(apiURL, headers: ["anthropic-version": "2023-06-01"], proxyPort: proxyPort)
            let elapsedMs = elapsedMilliseconds(since: started)
            let code = response.statusCode
            switch code {
            case 200...299:
                return Reading("HTTP \(code) · \(elapsedMs) ms", .response, severity: .ok, detail: "API 端点正常响应")
            case 401:
                return Reading("HTTP 401 · \(elapsedMs) ms", .response, severity: .ok, detail: "端点可达（无密钥请求返回鉴权要求属预期行为）")
            case 403:
                return Reading("HTTP 403 · 请求被拒绝 · \(elapsedMs) ms", .response, severity: .danger, detail: "出口 IP 或地区可能被 Anthropic / WAF 拒绝访问")
            case 407:
                return Reading("HTTP 407 · 代理需认证", .response, severity: .danger, detail: "代理服务器要求身份验证")
            case 429:
                return Reading("HTTP 429 · 触发限流 · \(elapsedMs) ms", .response, severity: .caution, detail: "该出口 IP 当前请求频次受限")
            case 500...599:
                return Reading("HTTP \(code) · 服务或网关错误 · \(elapsedMs) ms", .response, severity: .caution)
            default:
                return Reading("HTTP \(code) · \(elapsedMs) ms", .response, severity: .neutral)
            }
        } catch {
            return networkError(error)
        }
    }

    private static func probeClaudeWeb(proxyPort: Int?) async -> Reading {
        let started = ContinuousClock.now
        do {
            let (_, response) = try await httpRequest(claudeWebURL, method: "HEAD", proxyPort: proxyPort)
            let elapsedMs = elapsedMilliseconds(since: started)
            let code = response.statusCode
            switch code {
            case 200...399:
                return Reading("HTTP \(code) · \(elapsedMs) ms", .response, severity: .ok, detail: "claude.ai 入口可达")
            case 403:
                return Reading("HTTP 403 · \(elapsedMs) ms", .response, severity: .caution,
                               detail: "Cloudflare 人机质询或地区拦截（无浏览器指纹的 HEAD 请求触发 403 较常见，需结合出口地区综合判断）")
            default:
                return Reading("HTTP \(code) · \(elapsedMs) ms", .response, severity: .caution)
            }
        } catch {
            return networkError(error)
        }
    }

    static func httpRequest(
        _ url: URL,
        method: String = "GET",
        headers: [String: String] = [:],
        proxyPort: Int? = nil,
        proxyProtocol: UpstreamProxyProtocol = .httpConnect,
        timeout: TimeInterval = 7
    ) async throws -> (Data, HTTPURLResponse) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout + 3
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.urlCache = nil
        if let proxyPort {
            switch proxyProtocol {
            case .httpConnect:
                config.connectionProxyDictionary = [
                    kCFNetworkProxiesHTTPEnable as String: 1,
                    kCFNetworkProxiesHTTPProxy as String: "127.0.0.1",
                    kCFNetworkProxiesHTTPPort as String: proxyPort,
                    kCFNetworkProxiesHTTPSEnable as String: 1,
                    kCFNetworkProxiesHTTPSProxy as String: "127.0.0.1",
                    kCFNetworkProxiesHTTPSPort as String: proxyPort,
                ]
            case .socks5:
                config.connectionProxyDictionary = [
                    kCFNetworkProxiesSOCKSEnable as String: 1,
                    kCFNetworkProxiesSOCKSProxy as String: "127.0.0.1",
                    kCFNetworkProxiesSOCKSPort as String: proxyPort,
                ]
            }
        }

        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        request.httpMethod = method
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        let (bytes, response) = try await session.data(for: request, delegate: RejectRedirects())
        guard let httpResponse = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        return (bytes, httpResponse)
    }

    private static func elapsedMilliseconds(since start: ContinuousClock.Instant) -> Int {
        let duration = start.duration(to: .now)
        let ms = Double(duration.components.seconds) * 1000.0
            + Double(duration.components.attoseconds) / 1_000_000_000_000_000.0
        return max(1, Int(ms.rounded()))
    }

    private static func networkError(_ error: Error) -> Reading {
        let detail: String
        switch (error as? URLError)?.code {
        case .timedOut: detail = "请求超时"
        case .notConnectedToInternet: detail = "网络不可用"
        case .cannotFindHost, .dnsLookupFailed: detail = "域名解析失败"
        case .cannotConnectToHost: detail = "无法建立连接"
        case .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
             .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid:
            detail = "TLS 或证书校验失败"
        default: detail = "连接失败 · 错误 \((error as NSError).code)"
        }
        return Reading(detail, .failed, severity: .danger)
    }
}

private final class RejectRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}
