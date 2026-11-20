import AppKit
import Foundation
import Network
import UserNotifications

@MainActor
final class ProtectionGuardEngine: ObservableObject {
    enum TripKind: Equatable, Sendable {
        case unsupportedRegion
        case ipDrift
        case geoSplit
        case upstreamOffline
        case wakeVerifying
        case nodeSwitchVerifying
        case manual
    }

    enum Phase: Equatable, Sendable {
        case idle
        case starting
        case active
        case tripped(reason: String, kind: TripKind)
        case stopping

        var isRunning: Bool {
            switch self {
            case .active, .tripped: true
            case .idle, .starting, .stopping: false
            }
        }
    }

    private static let strictIPLockKey = "guardStrictIPLock.v1"
    private static let injectLocaleKey = "guardInjectProcessLocale.v1"
    private static let modeKey = "guardMode.v1"
    private static let autoStartGuardKey = "guardAutoStartOnLaunch.v1"

    @Published private(set) var protectionStatus: ClashProtection.Status?
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var busy = false
    @Published private(set) var verifying = false
    @Published private(set) var guardPort: Int?
    @Published private(set) var upstreamPort: Int?
    @Published private(set) var upstreamProtocol: UpstreamProxyProtocol = .httpConnect
    @Published private(set) var pinnedCountry: String?
    @Published private(set) var pinnedIP: String?
    @Published private(set) var lastVerifiedIP: String?
    @Published private(set) var lastVerifiedCountry: String?
    @Published private(set) var lastLatencyMs: Int?
    @Published private(set) var lastCheckedAt: Date?
    @Published private(set) var appliedProcessEnv: [String: String] = [:]
    @Published private(set) var activeTunnels: Int = 0
    @Published private(set) var auditStats: ConnectionAuditStats = .empty
    @Published private(set) var recentAuditEntries: [ConnectionAuditEntry] = []
    @Published private(set) var issue: String?
    @Published private(set) var note: String?
    @Published var portOverride = ""
    @Published private(set) var detectedPort: Int? = Clash.detectedPort()

    // Phase 3 + v1.2: Multi-client proxy discovery, Clash/Mihomo symbiosis & multi-client scripts
    @Published private(set) var discoveredClients: [DiscoveredProxyClient] = []
    @Published private(set) var discoveredControllers: [ClashControllerEndpoint] = []
    @Published private(set) var clashSnapshot: ClashControllerSnapshot?
    @Published private(set) var clashBusy = false
    @Published private(set) var clashError: String?
    @Published private(set) var clashActionNote: String?
    @Published private(set) var installedScriptTargets: [ProxyScriptTarget] = []
    @Published var selectedScriptTarget: ProxyScriptTarget = .clashVergeRev {
        didSet { refreshScriptStatus() }
    }
    @Published private(set) var clashScriptStatus: ClashScriptStatus = .vergeNotInstalled
    @Published var confirmRestoreVergeScript = false
    @Published var overrideFormat: OverrideFormat = .vergeJS
    @Published var copiedOverride = false
    @Published var selectedSwitchNode = ""

    // v1.2: Login item & silent auto-guard
    @Published private(set) var loginItemState: LoginItemState = LoginItemManager.currentState()
    @Published private(set) var loginItemNote: String?
    @Published private(set) var loginItemError: String?

    @Published var autoStartGuardOnLaunch: Bool {
        didSet {
            UserDefaults.standard.set(autoStartGuardOnLaunch, forKey: Self.autoStartGuardKey)
        }
    }

    @Published var selectedMode: ClashProtection.Mode {
        didSet {
            UserDefaults.standard.set(selectedMode.rawValue, forKey: Self.modeKey)
        }
    }

    @Published var strictIPLock: Bool {
        didSet {
            UserDefaults.standard.set(strictIPLock, forKey: Self.strictIPLockKey)
        }
    }

    @Published var injectProcessLocale: Bool {
        didSet {
            UserDefaults.standard.set(injectProcessLocale, forKey: Self.injectLocaleKey)
        }
    }

    private let protection = ClashProtection()
    private var proxy: CircuitBreakerProxy?
    private var watchdogTask: Task<Void, Never>?
    private var nodeWatchTask: Task<Void, Never>?
    private var lastWatchedRouteFingerprint: (mode: String, leafNode: String)?
    private var pathMonitor: NWPathMonitor?
    private var wakeObserver: NSObjectProtocol?
    private var lastPathRecheckAt: Date = .distantPast
    private var lastUpstreamFailureRecheckAt: Date = .distantPast
    private var lastNotifiedTripReason: String?

    init() {
        let savedMode = UserDefaults.standard.string(forKey: Self.modeKey)
            .flatMap(ClashProtection.Mode.init(rawValue:)) ?? .guardProxy
        self.selectedMode = savedMode
        self.strictIPLock = UserDefaults.standard.bool(forKey: Self.strictIPLockKey)
        self.injectProcessLocale = UserDefaults.standard.bool(forKey: Self.injectLocaleKey)
        self.autoStartGuardOnLaunch = UserDefaults.standard.bool(forKey: Self.autoStartGuardKey)
    }

    var portHint: String {
        if let port = detectedPort { return String(port) }
        if let httpClient = discoveredClients.first(where: { $0.protocols.supportsHTTP }) {
            return String(httpClient.port)
        }
        return "混合端口"
    }

    var activeSettingsPort: Int? {
        if case let .active(port, _, _, _) = protectionStatus { return port }
        return nil
    }

    var isGuardProxyRunning: Bool {
        proxy?.listeningPort != nil
    }

    var needsBackgroundKeepAlive: Bool {
        isGuardProxyRunning || phase.isRunning
    }

    var menuBarTitle: String {
        switch phase {
        case .idle:
            if case .recovery = protectionStatus { return "待恢复" }
            return ""
        case .starting:
            return "启动中"
        case .stopping:
            return "恢复中"
        case .tripped:
            return "已熔断"
        case .active:
            let region = lastVerifiedCountry ?? pinnedCountry ?? "已护卫"
            if let ms = lastLatencyMs {
                return "\(region) · \(ms)ms"
            }
            return region
        }
    }

    var menuBarIcon: String {
        switch phase {
        case .idle:
            if case .recovery = protectionStatus { return "exclamationmark.shield" }
            return "waveform.path.ecg"
        case .starting, .stopping:
            return "arrow.triangle.2.circlepath"
        case .tripped:
            return "exclamationmark.shield.fill"
        case .active:
            return "checkmark.shield.fill"
        }
    }

    func bootstrap() async {
        loginItemState = LoginItemManager.currentState()
        await refreshAuditLog()
        await refreshProtectionStatus()
        await refreshSymbiosis()
        requestNotificationAuthorizationIfBundled()
        if autoStartGuardOnLaunch && !isGuardProxyRunning {
            await autoStartGuardAfterLaunch()
        }
    }

    func refreshLoginItemState() {
        loginItemState = LoginItemManager.currentState()
    }

    func setLoginItemEnabled(_ enabled: Bool) {
        loginItemError = nil
        loginItemNote = nil
        do {
            loginItemState = try LoginItemManager.setEnabled(enabled)
            if enabled {
                loginItemNote = loginItemState == .requiresApproval
                    ? "已登记开机登录项，请在「系统设置 → 通用 → 登录项」中允许。"
                    : "已开启开机自动启动，重启 Mac 后将自动驻留菜单栏。"
            } else {
                loginItemNote = "已关闭开机自动启动。"
            }
        } catch {
            loginItemError = error.localizedDescription
            loginItemState = LoginItemManager.currentState()
        }
    }

    private func autoStartGuardAfterLaunch() async {
        // If crashed guard state exists, seamlessly recover it
        if case .recovery(_, .guardProxy, _, _) = protectionStatus {
            await resumeCrashedGuard()
            return
        }
        guard case .off = protectionStatus else { return }
        // Give proxy clients (Clash Verge / Mihomo Party) up to 20s after reboot to finish binding local ports
        for attempt in 0..<10 {
            if isGuardProxyRunning { return }
            if (try? resolveTargetUpstreamPort()) != nil {
                await startProtection()
                if isGuardProxyRunning { return }
            }
            if attempt < 9 {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                await refreshSymbiosis()
            }
        }
    }

    func refreshAuditLog() async {
        let snap = await ConnectionAuditLog.shared.snapshot(limit: 200)
        auditStats = snap.stats
        recentAuditEntries = snap.recent
    }

    func clearAuditLog() async {
        await ConnectionAuditLog.shared.clear()
        auditStats = .empty
        recentAuditEntries = []
    }

    // MARK: - Phase 3: Multi-Client Discovery & Clash/Mihomo Controller Symbiosis

    func refreshSymbiosis() async {
        guard !clashBusy else { return }
        clashBusy = true
        clashError = nil
        defer { clashBusy = false }

        async let clientsTask = ProxyClientDiscovery.scanRunningClients()
        async let controllersTask = ProxyClientDiscovery.discoverControllers()

        let clients = await clientsTask
        let controllers = await controllersTask

        discoveredClients = clients
        discoveredControllers = controllers

        if detectedPort == nil, let best = clients.first(where: { $0.protocols.supportsHTTP }) ?? clients.first {
            detectedPort = best.port
        }

        guard !controllers.isEmpty else {
            clashSnapshot = nil
            refreshScriptStatus()
            return
        }

        var lastErr: Error?
        for endpoint in controllers {
            do {
                let snap = try await ClashControllerClient.fetchSnapshot(endpoint: endpoint)
                clashSnapshot = snap
                if detectedPort == nil, let mp = snap.mixedPort {
                    detectedPort = mp
                }
                clashError = nil
                refreshScriptStatus()
                return
            } catch {
                lastErr = error
            }
        }
        clashSnapshot = nil
        clashError = lastErr?.localizedDescription
        refreshScriptStatus()
    }

    func refreshScriptStatus() {
        let found = ClashVergeScriptInstaller.discoverInstalledTargets()
        installedScriptTargets = found
        if !found.isEmpty && !found.contains(selectedScriptTarget) {
            selectedScriptTarget = found[0]
            return
        }
        clashScriptStatus = ClashVergeScriptInstaller.inspectStatus(
            target: selectedScriptTarget,
            liveSnapshot: clashSnapshot
        )
    }

    func installVergeScript() {
        clashError = nil
        clashActionNote = nil
        let target = selectedScriptTarget
        let preferred = clashSnapshot?.claudeRoute?.leafNode
        do {
            let chained = try ClashVergeScriptInstaller.install(target: target, preferredNodeName: preferred)
            refreshScriptStatus()
            let chainNote = chained ? "（已自动保留并串联你原有的自定义脚本）" : ""
            clashActionNote = "已一键写入 \(target.displayName) 防泄漏脚本（\(target.relativeScriptPath)）\(chainNote)。\(target.reloadHint)"
        } catch {
            clashError = error.localizedDescription
        }
    }

    func restoreVergeScript() {
        clashError = nil
        clashActionNote = nil
        let target = selectedScriptTarget
        do {
            try ClashVergeScriptInstaller.restore(target: target)
            refreshScriptStatus()
            clashActionNote = "已无损还原 \(target.displayName) 原始脚本。请在客户端重载配置以生效。"
        } catch {
            clashError = error.localizedDescription
        }
    }

    func openClashVergeForReload() {
        ClashVergeScriptInstaller.openClientApp(selectedScriptTarget)
    }

    func adoptDiscoveredPort(_ port: Int) {
        portOverride = String(port)
        note = "已选定上游代理端口 127.0.0.1:\(String(port))（启动守卫时将自动识别 HTTP/SOCKS5 协议）。"
    }

    func closeClashConnection(id: String) async {
        guard let endpoint = clashSnapshot?.endpoint else { return }
        clashBusy = true
        clashActionNote = nil
        defer { clashBusy = false }
        do {
            try await ClashControllerClient.closeConnection(endpoint: endpoint, id: id)
            clashActionNote = "已断开连接 \(id.prefix(8))。"
            clashBusy = false
            await refreshSymbiosis()
        } catch {
            clashError = error.localizedDescription
        }
    }

    func closeAllDirectViolations() async {
        guard let snap = clashSnapshot, !snap.directViolations.isEmpty else { return }
        clashBusy = true
        clashActionNote = nil
        var closed = 0
        for item in snap.directViolations {
            if (try? await ClashControllerClient.closeConnection(endpoint: snap.endpoint, id: item.id)) != nil {
                closed += 1
            }
        }
        clashBusy = false
        clashActionNote = "已切断 \(closed) 条 Claude 直连违规连接。"
        await refreshSymbiosis()
    }

    func switchClashNode(group: String, node: String) async {
        guard let endpoint = clashSnapshot?.endpoint else { return }
        clashBusy = true
        clashActionNote = nil
        defer { clashBusy = false }
        do {
            try await ClashControllerClient.switchGroupNode(endpoint: endpoint, group: group, node: node)
            clashActionNote = "已将代理组「\(group)」切换至「\(node)」。"
            clashBusy = false
            await refreshSymbiosis()
            if isGuardProxyRunning {
                await recheckNow()
            }
        } catch {
            clashError = error.localizedDescription
        }
    }

    // MARK: - Protection Lifecycle

    func refreshProtectionStatus() async {
        if protectionStatus == nil { issue = nil }
        do {
            let st = try await protection.status()
            protectionStatus = st
            switch st {
            case .off:
                appliedProcessEnv = [:]
                if !isGuardProxyRunning {
                    phase = .idle
                    guardPort = nil
                    upstreamPort = nil
                }
            case let .active(port, mode, savedUpstream, appliedEnv):
                appliedProcessEnv = appliedEnv
                if mode == .guardProxy {
                    if proxy?.listeningPort == port {
                        upstreamPort = savedUpstream ?? upstreamPort
                        guardPort = port
                    } else {
                        protectionStatus = .recovery(port: port, mode: mode, upstreamPort: savedUpstream, appliedEnv: appliedEnv)
                        phase = .idle
                        guardPort = port
                        upstreamPort = savedUpstream
                        issue = "检测到上次异常退出遗留的守护端口 127.0.0.1:\(port) 未监听，请点击「接管恢复守护」或「恢复原有设置」。"
                    }
                } else {
                    upstreamPort = savedUpstream ?? port
                    guardPort = nil
                    if phase == .idle {
                        phase = .active
                    }
                }
            case let .recovery(port, _, savedUpstream, appliedEnv):
                appliedProcessEnv = appliedEnv
                guardPort = port
                upstreamPort = savedUpstream
                if !isGuardProxyRunning {
                    phase = .idle
                }
            }
        } catch {
            protectionStatus = nil
            issue = error.localizedDescription
        }
    }

    func testUpstreamOnly() async {
        guard !busy else { return }
        busy = true
        issue = nil
        note = nil
        defer { busy = false }

        do {
            let port = try resolveTargetUpstreamPort()
            let proto = await detectUpstreamProtocol(port: port)
            let (_, resp) = try await Diagnostics.httpRequest(
                URL(string: "https://api.anthropic.com/v1/models")!,
                headers: ["anthropic-version": "2023-06-01"],
                proxyPort: port,
                proxyProtocol: proto,
                timeout: 6
            )
            let httpCode = resp.statusCode
            let geo = await ExitProbes.probeMultiSourceGeo(proxyPort: port, proxyProtocol: proto)
            let region = ClaudeRegions.displayName(for: geo.primaryCountryCode)
            let support = ClaudeRegions.support(for: geo.primaryCountryCode)
            let ipText = geo.primaryIP ?? "未知 IP"
            let protoTag = proto == .socks5 ? " · SOCKS5 上游" : ""
            switch support {
            case .supported:
                note = "代理 127.0.0.1:\(String(port)) 正常（HTTP \(httpCode)\(protoTag) · 出口 \(ipText) · \(region) · 支持地区）。"
            case .unsupported:
                issue = "代理 127.0.0.1:\(String(port)) 可连通（HTTP \(httpCode)\(protoTag)），但出口位于不支持地区 \(region)（\(ipText)），请先切换节点。"
            case .unknown:
                note = "通过 127.0.0.1:\(String(port)) 收到 Claude API HTTP \(httpCode)\(protoTag)，出口地区暂未识别。"
            }
        } catch {
            issue = error.localizedDescription
        }
    }

    func startProtection() async {
        guard !busy else { return }
        busy = true
        issue = nil
        note = nil
        phase = .starting
        defer { busy = false }

        do {
            let upstream = try resolveTargetUpstreamPort()
            let (httpCode, geo, latencyMs, proto) = try await verifyCompliantUpstreamExit(port: upstream)
            let exitCode = geo.primaryCountryCode!
            let exitIP = geo.primaryIP!

            var extraEnv: [String: String] = [:]
            if injectProcessLocale {
                let profile = ClaudeRegions.recommendedProcessLocale(
                    countryCode: exitCode,
                    geoTimeZone: geo.primaryTimeZone
                )
                extraEnv = [
                    "TZ": profile.timeZone,
                    "LANG": profile.lang,
                    "LC_ALL": profile.lang,
                ]
            }

            let localeSuffix = extraEnv.isEmpty ? "" : " · 进程 TZ=\(extraEnv["TZ"] ?? "")"
            let protoTag = proto == .socks5 ? "SOCKS5 " : ""

            if selectedMode == .guardProxy {
                let server = makeProxyServer()
                let boundPort = try await server.start(
                    preferredPort: 17899,
                    upstreamPort: upstream,
                    upstreamProtocol: proto,
                    initialState: .open(exitIP: exitIP, countryCode: exitCode)
                )
                do {
                    try await protection.start(
                        port: boundPort,
                        mode: .guardProxy,
                        upstreamPort: upstream,
                        extraEnv: extraEnv
                    )
                } catch {
                    server.stop()
                    throw error
                }
                self.proxy = server
                self.guardPort = boundPort
                self.upstreamPort = upstream
                self.upstreamProtocol = proto
                self.pinnedCountry = exitCode
                self.pinnedIP = exitIP
                self.lastVerifiedCountry = exitCode
                self.lastVerifiedIP = exitIP
                self.lastLatencyMs = latencyMs
                self.lastCheckedAt = Date()
                self.phase = .active
                self.lastNotifiedTripReason = nil
                await refreshProtectionStatus()
                startWatchdogAndObservers()
                note = "熔断守卫已启动：127.0.0.1:\(String(boundPort)) → \(protoTag):\(String(upstream))（\(ClaudeRegions.displayName(for: exitCode)) · HTTP \(httpCode)\(localeSuffix)）。请重启 Claude Code 生效。"
            } else {
                if proto == .socks5 {
                    throw CircuitBreakerError.listenerFailed("端口 :\(upstream) 为纯 SOCKS5 代理，请切至「熔断守卫模式」（本地网关会自动将 HTTP 桥接至 SOCKS5 上游）。")
                }
                try await protection.start(
                    port: upstream,
                    mode: .directClash,
                    upstreamPort: upstream,
                    extraEnv: extraEnv
                )
                self.guardPort = nil
                self.upstreamPort = upstream
                self.upstreamProtocol = proto
                self.pinnedCountry = exitCode
                self.pinnedIP = exitIP
                self.lastVerifiedCountry = exitCode
                self.lastVerifiedIP = exitIP
                self.lastLatencyMs = latencyMs
                self.lastCheckedAt = Date()
                self.phase = .active
                await refreshProtectionStatus()
                note = "已写入代理 127.0.0.1:\(String(upstream))（\(ClaudeRegions.displayName(for: exitCode)) · HTTP \(httpCode)\(localeSuffix)）。请重启 Claude Code。"
            }
        } catch {
            phase = .idle
            issue = error.localizedDescription
            await refreshProtectionStatus()
        }
    }

    func resumeCrashedGuard() async {
        guard !busy else { return }
        guard case let .recovery(savedGuardPort, .guardProxy, savedUpstream, _) = protectionStatus else {
            return
        }
        busy = true
        issue = nil
        note = nil
        phase = .starting
        defer { busy = false }

        do {
            let upstream = savedUpstream ?? detectedPort ?? Clash.validPort(portOverride)
            guard let upstream else { throw ProtectionError.invalidPort }
            let (httpCode, geo, latencyMs, proto) = try await verifyCompliantUpstreamExit(port: upstream)
            let exitCode = geo.primaryCountryCode!
            let exitIP = geo.primaryIP!

            let server = makeProxyServer()
            let boundPort = try await server.start(
                preferredPort: savedGuardPort,
                upstreamPort: upstream,
                upstreamProtocol: proto,
                initialState: .open(exitIP: exitIP, countryCode: exitCode)
            )
            guard boundPort == savedGuardPort else {
                server.stop()
                throw CircuitBreakerError.listenerFailed("原守护端口 \(savedGuardPort) 已被其他进程占用，请先恢复原有设置再重新启动。")
            }
            self.proxy = server
            self.guardPort = boundPort
            self.upstreamPort = upstream
            self.upstreamProtocol = proto
            self.pinnedCountry = exitCode
            self.pinnedIP = exitIP
            self.lastVerifiedCountry = exitCode
            self.lastVerifiedIP = exitIP
            self.lastLatencyMs = latencyMs
            self.lastCheckedAt = Date()
            self.phase = .active
            self.lastNotifiedTripReason = nil
            await refreshProtectionStatus()
            startWatchdogAndObservers()
            note = "已无缝接管守护端口 127.0.0.1:\(String(boundPort))（\(ClaudeRegions.displayName(for: exitCode)) · HTTP \(httpCode)）。"
        } catch {
            phase = .idle
            issue = error.localizedDescription
        }
    }

    func stopProtection() async {
        guard !busy else { return }
        busy = true
        issue = nil
        note = nil
        phase = .stopping
        defer { busy = false }

        stopWatchdogAndObservers()
        proxy?.stop()
        proxy = nil
        guardPort = nil
        upstreamPort = nil
        pinnedCountry = nil
        pinnedIP = nil
        activeTunnels = 0
        appliedProcessEnv = [:]
        lastNotifiedTripReason = nil

        do {
            let preserved = try await protection.stop()
            phase = .idle
            await refreshProtectionStatus()
            if protectionStatus == .off {
                note = preserved > 0
                    ? "已关闭熔断守卫并恢复设置（保留 \(preserved) 项手动调整）。请重启 Claude Code。"
                    : "已关闭熔断守卫并恢复原有代理与环境设置。请重启 Claude Code。"
            }
        } catch {
            phase = .idle
            issue = error.localizedDescription
            await refreshProtectionStatus()
        }
    }

    func shutdownBeforeTerminateSync() {
        stopWatchdogAndObservers()
        proxy?.stop()
        proxy = nil
        ClashProtection.restoreGuardModeOnTerminateSync()
    }

    func manualTrip() {
        guard isGuardProxyRunning else { return }
        tripBreaker(kind: .manual, reason: "用户手动开启熔断阻断（所有经守护端口的请求均已暂停）", notify: false)
    }

    func recheckNow(acceptNewIP: Bool = false) async {
        guard !verifying, let upstream = upstreamPort, isGuardProxyRunning else { return }
        verifying = true
        defer { verifying = false }

        let started = ContinuousClock.now
        let proto = upstreamProtocol
        async let geoTask = ExitProbes.probeMultiSourceGeo(proxyPort: upstream, proxyProtocol: proto)
        async let apiReachableTask: Int? = {
            do {
                let (_, resp) = try await Diagnostics.httpRequest(
                    URL(string: "https://api.anthropic.com/v1/models")!,
                    headers: ["anthropic-version": "2023-06-01"],
                    proxyPort: upstream,
                    proxyProtocol: proto,
                    timeout: 5.5
                )
                return resp.statusCode
            } catch {
                return nil
            }
        }()

        let geo = await geoTask
        let apiCode = await apiReachableTask
        let elapsedMs = elapsedMilliseconds(since: started)
        lastCheckedAt = Date()

        if let ip = geo.primaryIP {
            let sample = ExitSample(
                capturedAt: Date(),
                ip: ip,
                countryCode: geo.primaryCountryCode,
                asn: geo.networkASN,
                org: geo.networkOrg,
                networkKind: geo.networkKind,
                probePath: "熔断守卫 127.0.0.1:\(upstream)"
            )
            _ = await ExitHistoryStore.shared.record(sample)
        }

        guard let ip = geo.primaryIP, let countryCode = geo.primaryCountryCode else {
            tripBreaker(
                kind: .upstreamOffline,
                reason: "上游代理 127.0.0.1:\(upstream) 无法获取公网出口（可能已退出或断网）",
                notify: true
            )
            return
        }

        if case let .split(countries, _) = geo.consensus {
            lastVerifiedIP = ip
            lastVerifiedCountry = countryCode
            tripBreaker(
                kind: .geoSplit,
                reason: "检测到多源出口国家分流冲突（\(countries.joined(separator: " / "))），已阻断 Claude",
                notify: true
            )
            return
        }

        if ClaudeRegions.support(for: countryCode) != .supported {
            lastVerifiedIP = ip
            lastVerifiedCountry = countryCode
            let name = ClaudeRegions.displayName(for: countryCode)
            tripBreaker(
                kind: .unsupportedRegion,
                reason: "出口漂移至不支持地区 \(name)（\(ip)），已立即切断连接并阻断放行",
                notify: true
            )
            return
        }

        if apiCode == 403 {
            lastVerifiedIP = ip
            lastVerifiedCountry = countryCode
            tripBreaker(
                kind: .unsupportedRegion,
                reason: "通过 \(ClaudeRegions.displayName(for: countryCode))（\(ip)）访问 Claude API 返回 HTTP 403，已自动熔断",
                notify: true
            )
            return
        }

        if strictIPLock, let pinned = pinnedIP, pinned != ip, !acceptNewIP {
            lastVerifiedIP = ip
            lastVerifiedCountry = countryCode
            tripBreaker(
                kind: .ipDrift,
                reason: "严格锁 IP 已触发：出口由 \(pinned) 变为 \(ip)（\(ClaudeRegions.displayName(for: countryCode))），请确认后解除",
                notify: true
            )
            return
        }

        let wasTripped: Bool
        if case .tripped = phase { wasTripped = true } else { wasTripped = false }

        if acceptNewIP || pinnedIP == nil {
            pinnedIP = ip
            pinnedCountry = countryCode
        }
        lastVerifiedIP = ip
        lastVerifiedCountry = countryCode
        lastLatencyMs = elapsedMs
        issue = nil
        phase = .active
        proxy?.setGateState(.open(exitIP: ip, countryCode: countryCode))

        if wasTripped {
            lastNotifiedTripReason = nil
            note = "复检通过（\(ClaudeRegions.displayName(for: countryCode)) · \(ip) · \(elapsedMs)ms），已恢复 Claude 放行。"
            postNotification(
                title: "Claude 熔断守卫已恢复放行",
                body: "出口已确认合规：\(ClaudeRegions.displayName(for: countryCode))（\(ip)）"
            )
        }
    }

    // MARK: - Internal Watchdog & Event Observers

    private func tripBreaker(kind: TripKind, reason: String, notify: Bool) {
        proxy?.setGateState(.tripped(reason: reason))
        phase = .tripped(reason: reason, kind: kind)
        issue = reason
        if notify && lastNotifiedTripReason != reason {
            lastNotifiedTripReason = reason
            postNotification(title: "Claude 环境防护已自动熔断", body: reason)
        }
    }

    private func makeProxyServer() -> CircuitBreakerProxy {
        CircuitBreakerProxy(
            onAudit: { [weak self] entry in
                Task {
                    let result = await ConnectionAuditLog.shared.append(entry)
                    await MainActor.run {
                        self?.auditStats = result.stats
                        self?.recentAuditEntries = result.recent
                    }
                }
            },
            onTunnelCountChange: { [weak self] count in
                Task { @MainActor in
                    self?.activeTunnels = count
                }
            },
            onUpstreamFailure: { [weak self] _ in
                Task { @MainActor in
                    guard let self, self.isGuardProxyRunning else { return }
                    let now = Date()
                    guard now.timeIntervalSince(self.lastUpstreamFailureRecheckAt) >= 4 else { return }
                    self.lastUpstreamFailureRecheckAt = now
                    await self.recheckNow()
                }
            }
        )
    }

    private func startWatchdogAndObservers() {
        stopWatchdogAndObservers()

        watchdogTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let intervalNs: UInt64
                switch self.phase {
                case .tripped(_, .upstreamOffline), .tripped(_, .wakeVerifying), .tripped(_, .nodeSwitchVerifying):
                    intervalNs = 5_000_000_000
                case .tripped(_, .manual):
                    intervalNs = 30_000_000_000
                case .tripped:
                    intervalNs = 15_000_000_000
                default:
                    intervalNs = 30_000_000_000
                }
                try? await Task.sleep(nanoseconds: intervalNs)
                if Task.isCancelled { return }
                if case .tripped(_, .manual) = self.phase { continue }
                if self.isGuardProxyRunning {
                    await self.recheckNow()
                }
            }
        }

        // Ultra-fast 2-second local Clash controller watcher (<2ms Unix Socket, zero internet traffic):
        // Detects manual Clash node switches or mode changes immediately, pre-trips fail-closed, then re-verifies exit!
        lastWatchedRouteFingerprint = clashSnapshot.flatMap { snap in
            guard let leaf = snap.claudeRoute?.leafNode else { return nil }
            return (snap.mode.lowercased(), leaf)
        }
        nodeWatchTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if Task.isCancelled { return }
                guard let self, self.isGuardProxyRunning,
                      let endpoint = self.clashSnapshot?.endpoint else { continue }
                if case .tripped(_, .manual) = self.phase { continue }
                let targetGroup = self.clashSnapshot?.claudeRoute?.targetGroup
                guard let current = try? await ClashControllerClient.fetchQuickRouteFingerprint(
                    endpoint: endpoint,
                    ruleTargetGroup: targetGroup
                ) else { continue }

                if let prev = self.lastWatchedRouteFingerprint {
                    if prev.mode != current.mode || prev.leafNode != current.leafNode {
                        self.lastWatchedRouteFingerprint = current
                        // Pre-trip fail-closed immediately so ZERO requests leak during node switch!
                        self.tripBreaker(
                            kind: .nodeSwitchVerifying,
                            reason: "检测到 Clash 切换（\(prev.leafNode) → \(current.leafNode)），已秒级预熔断并复检出口…",
                            notify: false
                        )
                        await self.recheckNow()
                    }
                } else {
                    self.lastWatchedRouteFingerprint = current
                }
            }
        }

        let monitor = NWPathMonitor()
        let monitorQueue = DispatchQueue(label: "local.claude-environment-check.path-monitor")
        monitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor in
                guard let self, self.isGuardProxyRunning else { return }
                let now = Date()
                guard now.timeIntervalSince(self.lastPathRecheckAt) >= 2.5 else { return }
                self.lastPathRecheckAt = now
                if case .tripped(_, .manual) = self.phase { return }
                await self.recheckNow()
            }
        }
        monitor.start(queue: monitorQueue)
        self.pathMonitor = monitor

        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.isGuardProxyRunning else { return }
                if case .tripped(_, .manual) = self.phase { return }
                self.tripBreaker(kind: .wakeVerifying, reason: "系统从休眠唤醒，正在复检出口合规性…", notify: false)
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                await self.recheckNow()
            }
        }
    }

    private func stopWatchdogAndObservers() {
        watchdogTask?.cancel()
        watchdogTask = nil
        nodeWatchTask?.cancel()
        nodeWatchTask = nil
        lastWatchedRouteFingerprint = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
            self.wakeObserver = nil
        }
    }

    private func resolveTargetUpstreamPort() throws -> Int {
        if portOverride.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            detectedPort = Clash.detectedPort()
                ?? discoveredClients.first(where: { $0.protocols.supportsHTTP })?.port
                ?? discoveredClients.first?.port
                ?? clashSnapshot?.mixedPort
            guard let port = detectedPort else { throw ProtectionError.invalidPort }
            return port
        }
        guard let port = Clash.validPort(portOverride) else { throw ProtectionError.invalidPort }
        return port
    }

    private func detectUpstreamProtocol(port: Int) async -> UpstreamProxyProtocol {
        let support = await Task.detached(priority: .userInitiated) {
            ProxyClientDiscovery.probePortProtocols(port: port)
        }.value
        return (support == .socks5Only) ? .socks5 : .httpConnect
    }

    private func verifyCompliantUpstreamExit(port: Int) async throws -> (Int, MultiSourceGeoReport, Int, UpstreamProxyProtocol) {
        let started = ContinuousClock.now
        let proto = await detectUpstreamProtocol(port: port)
        let httpCode: Int
        if proto == .socks5 {
            let (_, resp) = try await Diagnostics.httpRequest(
                URL(string: "https://api.anthropic.com/v1/models")!,
                headers: ["anthropic-version": "2023-06-01"],
                proxyPort: port,
                proxyProtocol: .socks5,
                timeout: 6
            )
            httpCode = resp.statusCode
        } else {
            httpCode = try await Task.detached(priority: .userInitiated) { try Clash.probe(port: port) }.value
        }
        let geo = await ExitProbes.probeMultiSourceGeo(proxyPort: port, proxyProtocol: proto)
        let latencyMs = elapsedMilliseconds(since: started)

        guard geo.primaryIP != nil, let code = geo.primaryCountryCode else {
            throw ProtectionError.exitGeoUnavailable
        }
        if case let .split(countries, _) = geo.consensus {
            throw ProtectionError.exitGeoSplit(countries.joined(separator: " / "))
        }
        guard ClaudeRegions.support(for: code) == .supported else {
            throw ProtectionError.unsupportedExitRegion(ClaudeRegions.displayName(for: code))
        }
        return (httpCode, geo, latencyMs, proto)
    }

    private func elapsedMilliseconds(since start: ContinuousClock.Instant) -> Int {
        let duration = start.duration(to: .now)
        let ms = Double(duration.components.seconds) * 1000.0
            + Double(duration.components.attoseconds) / 1_000_000_000_000_000.0
        return max(1, Int(ms.rounded()))
    }

    private var canUseUserNotifications: Bool {
        Bundle.main.bundleURL.pathExtension == "app" && Bundle.main.bundleIdentifier != nil
    }

    private func requestNotificationAuthorizationIfBundled() {
        guard canUseUserNotifications else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func postNotification(title: String, body: String) {
        guard canUseUserNotifications else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
    }
}
