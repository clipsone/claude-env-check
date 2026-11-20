import AppKit
import SwiftUI
import UniformTypeIdentifiers

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var guardEngine: ProtectionGuardEngine?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationWillTerminate(_ notification: Notification) {
        guardEngine?.shutdownBeforeTerminateSync()
    }
}

@main
struct EnvironmentCheckApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var guardEngine: ProtectionGuardEngine
    @StateObject private var workbench: WorkbenchController
    @StateObject private var model: CheckModel

    init() {
        let engine = ProtectionGuardEngine()
        _guardEngine = StateObject(wrappedValue: engine)
        _workbench = StateObject(wrappedValue: WorkbenchController())
        _model = StateObject(wrappedValue: CheckModel(guardEngine: engine))
    }

    var body: some Scene {
        Window("Claude 环境体检", id: "main") {
            CheckView(model: model, guardEngine: guardEngine, workbench: workbench)
                .tint(.teal)
                .frame(minWidth: 960, minHeight: 680)
                .task {
                    appDelegate.guardEngine = guardEngine
                    await guardEngine.bootstrap()
                    await workbench.refreshAll()
                    await model.refreshHistory()
                    if model.current == nil {
                        await model.scan(online: false)
                    }
                }
        }
        .defaultSize(width: 1120, height: 840)

        MenuBarExtra {
            MenuBarPopoverView(model: model, guardEngine: guardEngine)
                .tint(.teal)
        } label: {
            HStack(spacing: 4) {
                Image(systemName: guardEngine.menuBarIcon)
                if !guardEngine.menuBarTitle.isEmpty {
                    Text(verbatim: guardEngine.menuBarTitle)
                }
            }
        }
        .menuBarExtraStyle(.window)
    }
}

private enum CheckPage: String, CaseIterable, Identifiable {
    case readings = "检测结果"
    case symbiosis = "代理共生"
    case workbench = "工作台"
    case audit = "连接审计"
    case comparison = "基线对比"
    case history = "出口历史"

    var id: Self { self }
}

private enum ProbeRoutePreference: String, CaseIterable, Identifiable {
    case auto = "自动"
    case system = "系统网络"
    case proxy = "保护代理"

    var id: Self { self }
}

private enum AuditFilter: String, CaseIterable, Identifiable {
    case all = "全部"
    case allowed = "已放行"
    case blocked = "已熔断"
    case errors = "上游异常"

    var id: Self { self }
}

private struct NamedSnapshot: Codable, Identifiable, Sendable {
    let id: UUID
    let label: String
    let snapshot: Snapshot
}

@MainActor
private final class CheckModel: ObservableObject {
    private static let legacyBaselineKey = "environmentBaseline.v2"
    private static let snapshotsKey = "environmentSnapshots.v1"
    private static let maxSnapshots = 10

    let guardEngine: ProtectionGuardEngine

    @Published private(set) var current: Snapshot?
    @Published private(set) var savedSnapshots: [NamedSnapshot] = []
    @Published var selectedBaselineID: UUID?
    @Published var snapshotLabelDraft = ""
    @Published private(set) var historySummary: ExitDriftSummary = .empty
    @Published private(set) var scanning = false
    @Published private(set) var baselineIssue: String?
    @Published var page = CheckPage.readings
    @Published var routePreference = ProbeRoutePreference.auto
    @Published var changesOnly = false
    @Published var auditSearch = ""
    @Published var auditFilter = AuditFilter.all
    @Published var auditClaudeOnly = false
    @Published var confirmClearBaselines = false
    @Published var confirmClearHistory = false
    @Published var confirmClearAudit = false
    @Published private(set) var copiedReport = false
    @Published private(set) var exportMessage: String?

    init(guardEngine: ProtectionGuardEngine) {
        self.guardEngine = guardEngine
        loadSavedSnapshots()
    }

    var selectedBaseline: NamedSnapshot? {
        if let id = selectedBaselineID, let found = savedSnapshots.first(where: { $0.id == id }) {
            return found
        }
        return savedSnapshots.first
    }

    var effectiveProbeRoute: ProbeRoute {
        switch routePreference {
        case .system:
            return .system
        case .proxy:
            if let active = guardEngine.activeSettingsPort { return .localProxy(active) }
            if let manual = Clash.validPort(guardEngine.portOverride) { return .localProxy(manual) }
            if let detected = guardEngine.detectedPort { return .localProxy(detected) }
            return .system
        case .auto:
            if let active = guardEngine.activeSettingsPort { return .localProxy(active) }
            return .system
        }
    }

    func scan(online: Bool) async {
        guard !scanning else { return }
        scanning = true
        defer { scanning = false }
        let route = online ? effectiveProbeRoute : .system
        current = await Diagnostics.capture(online: online, route: route)
        await refreshHistory()
    }

    func refreshHistory() async {
        historySummary = await ExitHistoryStore.shared.summary()
    }

    func clearHistory() async {
        await ExitHistoryStore.shared.clear()
        historySummary = .empty
        if let current {
            await scan(online: current.online)
        }
    }

    func copyReport() {
        guard let current else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(current.markdownReport(), forType: .string)
        copiedReport = true
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            copiedReport = false
        }
    }

    func saveCurrentAsSnapshot() {
        guard !scanning, let current else { return }
        let rawLabel = snapshotLabelDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        let defaultLabel = "\(current.online ? "联网" : "本机") · \(current.probeRouteDescription) · \(current.capturedAt.formatted(date: .omitted, time: .shortened))"
        let entry = NamedSnapshot(
            id: UUID(),
            label: rawLabel.isEmpty ? defaultLabel : rawLabel,
            snapshot: current
        )
        savedSnapshots.insert(entry, at: 0)
        if savedSnapshots.count > Self.maxSnapshots {
            savedSnapshots = Array(savedSnapshots.prefix(Self.maxSnapshots))
        }
        selectedBaselineID = entry.id
        snapshotLabelDraft = ""
        persistSnapshots()
    }

    func deleteSnapshot(_ id: UUID) {
        savedSnapshots.removeAll { $0.id == id }
        if selectedBaselineID == id {
            selectedBaselineID = savedSnapshots.first?.id
        }
        persistSnapshots()
    }

    func clearAllSnapshots() {
        savedSnapshots = []
        selectedBaselineID = nil
        UserDefaults.standard.removeObject(forKey: Self.snapshotsKey)
        UserDefaults.standard.removeObject(forKey: Self.legacyBaselineKey)
        baselineIssue = nil
    }

    private func loadSavedSnapshots() {
        if let bytes = UserDefaults.standard.data(forKey: Self.snapshotsKey) {
            do {
                let decoded = try JSONDecoder().decode([NamedSnapshot].self, from: bytes)
                savedSnapshots = decoded
                selectedBaselineID = decoded.first?.id
                return
            } catch {
                baselineIssue = "部分保存的快照无法读取，可重新保存当前采样。"
            }
        }
        // Auto-migrate single baseline from v0.3/v0.5
        if let legacy = UserDefaults.standard.data(forKey: Self.legacyBaselineKey),
           let snap = try? JSONDecoder().decode(Snapshot.self, from: legacy) {
            let migrated = NamedSnapshot(id: UUID(), label: "历史基线", snapshot: snap)
            savedSnapshots = [migrated]
            selectedBaselineID = migrated.id
            persistSnapshots()
        }
    }

    private func persistSnapshots() {
        do {
            let bytes = try JSONEncoder().encode(savedSnapshots)
            UserDefaults.standard.set(bytes, forKey: Self.snapshotsKey)
            baselineIssue = nil
        } catch {
            baselineIssue = "保存快照失败。"
        }
    }

    func exportAudit(asCSV: Bool) async {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.allowedContentTypes = asCSV ? [.commaSeparatedText] : [.json]
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        panel.nameFieldStringValue = "claude-env-audit-\(stamp).\(asCSV ? "csv" : "json")"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            if asCSV {
                let csv = await ConnectionAuditLog.shared.exportCSV()
                try Data(csv.utf8).write(to: url, options: .atomic)
            } else if let json = await ConnectionAuditLog.shared.exportJSON() {
                try json.write(to: url, options: .atomic)
            }
            exportMessage = "已导出至 \(url.lastPathComponent)"
            Task {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                exportMessage = nil
            }
        } catch {
            exportMessage = "导出失败：\(error.localizedDescription)"
        }
    }
}

// MARK: - Menu Bar Popover

private struct MenuBarPopoverView: View {
    @ObservedObject var model: CheckModel
    @ObservedObject var guardEngine: ProtectionGuardEngine
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: guardEngine.menuBarIcon)
                    .font(.title3)
                    .foregroundStyle(statusColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Claude 环境体检")
                        .font(.headline)
                    Text(statusSubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer()
            }

            Divider()

            if guardEngine.isGuardProxyRunning {
                VStack(alignment: .leading, spacing: 6) {
                    infoRow("守护端口", "127.0.0.1:\(String(guardEngine.guardPort ?? 0)) → :\(String(guardEngine.upstreamPort ?? 0))")
                    if let ip = guardEngine.lastVerifiedIP {
                        infoRow("验证出口", "\(ip) · \(ClaudeRegions.shortName(for: guardEngine.lastVerifiedCountry))")
                    }
                    if let tz = guardEngine.appliedProcessEnv["TZ"] {
                        infoRow("进程时区", tz)
                    }
                    infoRow("连接统计", "放行 \(guardEngine.auditStats.allowed) · 熔断 \(guardEngine.auditStats.blocked) · 活跃 \(guardEngine.activeTunnels)")
                    if let checked = guardEngine.lastCheckedAt {
                        infoRow("上次巡检", checked.formatted(date: .omitted, time: .standard))
                    }
                }
                .font(.caption)

                Divider()

                VStack(spacing: 6) {
                    HStack(spacing: 8) {
                        Button {
                            Task { await guardEngine.recheckNow() }
                        } label: {
                            Label(guardEngine.verifying ? "巡检中…" : "立即复检", systemImage: "arrow.clockwise")
                                .frame(maxWidth: .infinity)
                        }
                        .disabled(guardEngine.verifying)

                        if case let .tripped(_, kind) = guardEngine.phase {
                            Button {
                                Task { await guardEngine.recheckNow(acceptNewIP: kind == .ipDrift) }
                            } label: {
                                Label("复检解除", systemImage: "lock.open")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(guardEngine.verifying)
                        } else {
                            Button {
                                guardEngine.manualTrip()
                            } label: {
                                Label("紧急熔断", systemImage: "hand.raised")
                                    .frame(maxWidth: .infinity)
                            }
                        }
                    }

                    Button(role: .destructive) {
                        Task {
                            await guardEngine.stopProtection()
                            await model.scan(online: false)
                        }
                    } label: {
                        Text("关闭防护并恢复配置")
                            .frame(maxWidth: .infinity)
                    }
                    .disabled(guardEngine.busy)
                }
            } else {
                if case .recovery = guardEngine.protectionStatus {
                    Text("检测到上次遗留的代理配置，请打开主窗口恢复或接管守护。")
                        .font(.caption)
                        .foregroundStyle(.orange)
                } else {
                    Text("当前未开启实时熔断守卫。点击下方快速启动或打开主窗口。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button {
                        Task {
                            await guardEngine.startProtection()
                            await model.scan(online: false)
                        }
                    } label: {
                        Label("启动熔断守卫", systemImage: "shield")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(guardEngine.busy)
                }
            }

            Divider()

            HStack {
                Button("打开主窗口") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                Spacer()
                Button(guardEngine.isGuardProxyRunning ? "退出并恢复" : "退出") {
                    guardEngine.shutdownBeforeTerminateSync()
                    NSApp.terminate(nil)
                }
            }
        }
        .padding(14)
        .frame(width: 306)
    }

    private var statusColor: Color {
        switch guardEngine.phase {
        case .active: .teal
        case .tripped: .red
        case .starting, .stopping: .orange
        case .idle: .secondary
        }
    }

    private var statusSubtitle: String {
        switch guardEngine.phase {
        case .active:
            let region = ClaudeRegions.displayName(for: guardEngine.lastVerifiedCountry ?? guardEngine.pinnedCountry)
            return "实时护卫中 · \(region)"
        case .tripped(let reason, _):
            return reason
        case .starting:
            return "正在验证出口并启动本地守护端口…"
        case .stopping:
            return "正在停止守护并恢复配置…"
        case .idle:
            return "未启用实时熔断守卫"
        }
    }

    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).font(.system(.caption, design: .monospaced))
        }
    }
}

// MARK: - Main Window View

private struct CheckView: View {
    @ObservedObject var model: CheckModel
    @ObservedObject var guardEngine: ProtectionGuardEngine
    @ObservedObject var workbench: WorkbenchController

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if let current = model.current {
                        switch model.page {
                        case .readings: readings(current)
                        case .symbiosis: ClashSymbiosisView(guardEngine: guardEngine)
                        case .workbench:
                            WorkbenchView(
                                workbench: workbench,
                                guardEngine: guardEngine,
                                activeProxyPort: model.effectiveProbeRoute.proxyPort ?? guardEngine.detectedPort,
                                exitCountryCode: current.observedExitCountry,
                                exitTimeZone: current.observedExitTimeZone
                            )
                        case .audit: auditView
                        case .comparison: comparison(current)
                        case .history: historyView
                        }
                    } else {
                        ProgressView("正在读取本机与 Claude 配置…")
                            .frame(maxWidth: .infinity, minHeight: 260)
                    }
                }
                .padding(.horizontal, 28)
                .padding(.vertical, 22)
            }
            .id(model.page)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .confirmationDialog("清除全部已保存的基线快照？", isPresented: $model.confirmClearBaselines, titleVisibility: .visible) {
            Button("清除全部快照", role: .destructive) { model.clearAllSnapshots() }
        }
        .confirmationDialog("清空 48 小时出口历史记录？", isPresented: $model.confirmClearHistory, titleVisibility: .visible) {
            Button("清空历史", role: .destructive) { Task { await model.clearHistory() } }
        }
        .confirmationDialog("清空 48 小时连接审计日志？", isPresented: $model.confirmClearAudit, titleVisibility: .visible) {
            Button("清空日志", role: .destructive) { Task { await guardEngine.clearAuditLog() } }
        }
    }

    private var header: some View {
        let violationCount = guardEngine.clashSnapshot?.directViolations.count ?? 0
        return VStack(alignment: .leading, spacing: 15) {
            HStack(alignment: .center, spacing: 16) {
                HStack(spacing: 13) {
                    Image(systemName: "waveform.path.ecg")
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundStyle(.teal)
                        .frame(width: 48, height: 48)
                        .background(.teal.opacity(0.11), in: RoundedRectangle(cornerRadius: 12))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text("Claude 环境体检")
                                .font(.system(size: 26, weight: .semibold))
                                .accessibilityAddTraits(.isHeader)
                            Text("v1.2.0")
                                .font(.caption.weight(.medium))
                                .foregroundStyle(.teal)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 2)
                                .background(.teal.opacity(0.12), in: Capsule())
                        }
                        Text("无 Root 本地熔断守卫 · Clash/Mihomo 深度共生 · Claude 全家桶安全工作台")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 12)
                HStack(spacing: 9) {
                    Button {
                        model.copyReport()
                    } label: {
                        Label(model.copiedReport ? "已复制" : "复制报告",
                              systemImage: model.copiedReport ? "checkmark" : "doc.on.doc")
                    }
                    .disabled(model.current == nil)
                    .help("复制脱敏 Markdown 体检报告到剪贴板")

                    Button {
                        Task { await model.scan(online: false) }
                    } label: {
                        Label("本机检测", systemImage: "arrow.clockwise")
                    }
                    .keyboardShortcut("r", modifiers: [.command])

                    Button {
                        Task { await model.scan(online: true) }
                    } label: {
                        Label("联网检测", systemImage: "globe")
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                    .help("执行全链路联网合规、多源 GeoIP、IPv6 与真实 DNS 递归出口探测")
                }
                .controlSize(.large)
                .disabled(model.scanning)
            }

            HStack(spacing: 12) {
                Picker("工作页", selection: $model.page) {
                    ForEach(CheckPage.allCases) { option in
                        if option == .audit && guardEngine.auditStats.blocked > 0 {
                            Text("\(option.rawValue) (\(guardEngine.auditStats.blocked))").tag(option)
                        } else if option == .symbiosis && violationCount > 0 {
                            Text("\(option.rawValue) (!\(violationCount))").tag(option)
                        } else {
                            Text(option.rawValue).tag(option)
                        }
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 470)

                Divider().frame(height: 16)

                HStack(spacing: 6) {
                    Text("联网路径")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize()
                    Picker("联网路径", selection: $model.routePreference) {
                        ForEach(ProbeRoutePreference.allCases) { pref in
                            Text(pref.rawValue).tag(pref)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .frame(width: 84)
                    Text(verbatim: model.effectiveProbeRoute.shortBadge)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(Color(nsColor: .controlBackgroundColor), in: Capsule())
                        .overlay { Capsule().strokeBorder(.quaternary) }
                        .help(model.effectiveProbeRoute.label)
                }

                Spacer(minLength: 8)

                if model.scanning {
                    ProgressView()
                        .controlSize(.small)
                    Text("检测中…")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize()
                } else if let current = model.current {
                    Text("采样于 \(current.capturedAt.formatted(date: .abbreviated, time: .standard))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }
            }
        }
        .padding(.horizontal, 28)
        .padding(.top, 20)
        .padding(.bottom, 14)
    }

    // MARK: - Readings Page

    private func readings(_ current: Snapshot) -> some View {
        let verdict = current.verdict
        return VStack(alignment: .leading, spacing: 18) {
            verdictBanner(verdict)
            protectionSection

            VStack(alignment: .leading, spacing: 10) {
                sectionTitle("核心联网实测", icon: "antenna.radiowaves.left.and.right")
                HStack(alignment: .top, spacing: 12) {
                    highlightProbe(.egressRegion, snapshot: current)
                    highlightProbe(.api, snapshot: current)
                    highlightProbe(.dnsLeak, snapshot: current)
                }
            }

            HStack(alignment: .top, spacing: 16) {
                groupCard(
                    "出口合规与稳定性",
                    icon: "globe.asia.australia",
                    ids: [.claudeWeb, .geoConsensus, .exitQuality, .ipReputation, .ipv6Leak, .exitDrift],
                    snapshot: current
                )
                groupCard(
                    "Claude 客户端与配置审计",
                    icon: "terminal",
                    ids: [.claudeCLI, .claudeProxyConfig, .configConflicts, .desktop],
                    snapshot: current
                )
            }

            HStack(alignment: .top, spacing: 16) {
                groupCard(
                    "DNS 与系统代理链路",
                    icon: "network",
                    ids: [.tunCapture, .proxy, .dns],
                    snapshot: current
                )
                groupCard(
                    "本机区域环境",
                    icon: "desktopcomputer",
                    ids: [.timeZone, .language, .locale, .system],
                    snapshot: current
                )
            }
        }
    }

    private func verdictBanner(_ verdict: EnvironmentVerdict) -> some View {
        let accent = verdictColor(verdict.level)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: verdictIcon(verdict.level))
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(accent)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(verdict.headline)
                        .font(.headline)
                    Text(verdict.summary)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 10)
                HStack(spacing: 6) {
                    if verdict.okCount > 0 { counterPill("通过 \(verdict.okCount)", color: .teal) }
                    if verdict.cautionCount > 0 { counterPill("注意 \(verdict.cautionCount)", color: .orange) }
                    if verdict.dangerCount > 0 { counterPill("高危 \(verdict.dangerCount)", color: .red) }
                    if verdict.pendingCount > 0 { counterPill("待测 \(verdict.pendingCount)", color: .secondary) }
                }
            }

            if !verdict.actions.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("建议处理项")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        if verdict.actions.contains(where: { $0.id == "dns-leak" || $0.id == "exit-drift" }) {
                            Button("前往「代理共生」获取防泄漏规则 →") {
                                model.page = .symbiosis
                            }
                            .buttonStyle(.link)
                            .font(.caption)
                        }
                    }
                    ForEach(verdict.actions.prefix(5)) { action in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: action.severity == .danger ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(action.severity == .danger ? .red : .orange)
                                .padding(.top, 2)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(action.title)
                                    .font(.callout.weight(.medium))
                                Text(action.guidance)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            if action.id == "exit-drift" {
                                Spacer(minLength: 8)
                                Button("确认已固定，清空 48h 记录") {
                                    Task { await model.clearHistory() }
                                }
                                .controlSize(.small)
                                .disabled(model.scanning)
                            }
                        }
                    }
                }
            }
        }
        .padding(16)
        .background(accent.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(accent.opacity(0.24)) }
    }

    private func counterPill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption.weight(.medium))
            .foregroundStyle(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.12), in: Capsule())
    }

    // MARK: - Guard Protection Section

    private var protectionSection: some View {
        let isTripped: Bool = {
            if case .tripped = guardEngine.phase { return true }
            return false
        }()
        let borderColor: Color = isTripped ? .red.opacity(0.45) : (guardEngine.isGuardProxyRunning ? .teal.opacity(0.35) : .clear)

        return VStack(alignment: .leading, spacing: 11) {
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        sectionTitle("环境防护与本地熔断守卫", icon: isTripped ? "exclamationmark.shield.fill" : "shield.lefthalf.filled")
                        if guardEngine.isGuardProxyRunning {
                            counterPill(
                                isTripped ? "已熔断 · 仅阻断 Claude" : "护卫中 · 活跃隧道 \(guardEngine.activeTunnels)",
                                color: isTripped ? .red : .teal
                            )
                        }
                        if let tz = guardEngine.appliedProcessEnv["TZ"] {
                            counterPill("进程 TZ=\(tz)", color: .teal)
                        }
                    }
                    Text("零 Root 共生现有代理：在 127.0.0.1 建立透明熔断网关，出口漂移至不支持地区或代理掉线时毫秒级仅切断 Claude，可选进程级 TZ/LANG 对齐而绝不改 macOS 全局时区")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 10)
                if guardEngine.busy || guardEngine.verifying {
                    ProgressView().controlSize(.small)
                }
                protectionControls
            }

            if guardEngine.isGuardProxyRunning {
                Divider()
                HStack(spacing: 14) {
                    if let gPort = guardEngine.guardPort, let uPort = guardEngine.upstreamPort {
                        let protoPrefix = guardEngine.upstreamProtocol == .socks5 ? "SOCKS5 " : "上游 "
                        Label("127.0.0.1:\(String(gPort)) → \(protoPrefix):\(String(uPort))", systemImage: "arrow.triangle.branch")
                            .font(.system(.caption, design: .monospaced))
                    }
                    if let ip = guardEngine.lastVerifiedIP {
                        Label("\(ip) · \(ClaudeRegions.displayName(for: guardEngine.lastVerifiedCountry))", systemImage: "mappin.and.ellipse")
                            .font(.caption)
                    }
                    if let ms = guardEngine.lastLatencyMs {
                        Label("\(String(ms)) ms", systemImage: "speedometer")
                            .font(.system(.caption, design: .monospaced))
                    }
                    Spacer()
                    Toggle("锁定固定出口 IP", isOn: $guardEngine.strictIPLock)
                        .toggleStyle(.checkbox)
                        .font(.caption)
                        .help("开启后，即使同国家更换出口 IP 也会触发熔断，需人工确认后放行")
                    if let checked = guardEngine.lastCheckedAt {
                        Text("巡检 \(checked.formatted(date: .omitted, time: .standard))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .foregroundStyle(.secondary)
            } else if case .off = guardEngine.protectionStatus {
                HStack(spacing: 16) {
                    Picker("防护模式", selection: $guardEngine.selectedMode) {
                        ForEach(ClashProtection.Mode.allCases, id: \.self) { m in
                            Text(m.title).tag(m)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 300)

                    if guardEngine.selectedMode == .guardProxy {
                        Toggle("严格锁出口 IP", isOn: $guardEngine.strictIPLock)
                            .toggleStyle(.checkbox)
                            .font(.callout)
                    }

                    Toggle("进程级对齐 TZ / LANG（不改系统时区）", isOn: $guardEngine.injectProcessLocale)
                        .toggleStyle(.checkbox)
                        .font(.callout)
                        .help("按实测出口地区自动写入 Claude Code 的 TZ/LANG/LC_ALL 环境变量，关闭防护时无损恢复")

                    Spacer()
                }
            }

            if case let .tripped(reason, kind) = guardEngine.phase {
                HStack(alignment: .center, spacing: 10) {
                    Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                    Text(reason).font(.callout.weight(.medium)).foregroundStyle(.red)
                    Spacer()
                    Button("立即复检") { Task { await guardEngine.recheckNow() } }
                        .disabled(guardEngine.verifying)
                    if kind == .ipDrift {
                        Button("接受新 IP 并解除") { Task { await guardEngine.recheckNow(acceptNewIP: true) } }
                            .buttonStyle(.borderedProminent)
                            .disabled(guardEngine.verifying)
                    }
                }
                .padding(10)
                .background(.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            } else if let issue = guardEngine.issue {
                Label(issue, systemImage: "exclamationmark.circle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if let note = guardEngine.note {
                Text(note)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(15)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay {
            RoundedRectangle(cornerRadius: 11)
                .strokeBorder(borderColor == .clear ? Color.primary.opacity(0.08) : borderColor, lineWidth: isTripped ? 1.5 : 1)
        }
    }

    @ViewBuilder
    private var protectionControls: some View {
        HStack(spacing: 8) {
            switch guardEngine.protectionStatus {
            case .none:
                Button("重新读取状态") { Task { await guardEngine.refreshProtectionStatus() } }

            case .off:
                Text("127.0.0.1")
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
                TextField("代理端口", text: $guardEngine.portOverride, prompt: Text(guardEngine.portHint))
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 74)
                    .help("留空自动识别 Clash Verge 或扫描到的本机代理端口")
                Button("测试上游") { Task { await guardEngine.testUpstreamOnly() } }
                Button(guardEngine.selectedMode == .guardProxy ? "启动熔断守卫" : "写入代理") {
                    Task {
                        await guardEngine.startProtection()
                        await model.scan(online: false)
                    }
                }
                .buttonStyle(.borderedProminent)

            case let .active(port, mode, _, _):
                if mode == .guardProxy && guardEngine.isGuardProxyRunning {
                    Button("立即复检") { Task { await guardEngine.recheckNow() } }
                        .disabled(guardEngine.verifying)
                    if case .active = guardEngine.phase {
                        Button("手动熔断") { guardEngine.manualTrip() }
                    }
                    Button("关闭并恢复") {
                        Task {
                            await guardEngine.stopProtection()
                            await model.scan(online: false)
                        }
                    }
                } else {
                    Label("直写模式 · :\(String(port))", systemImage: "checkmark.shield")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(.teal)
                    Button("关闭并恢复") {
                        Task {
                            await guardEngine.stopProtection()
                            await model.scan(online: false)
                        }
                    }
                }

            case let .recovery(_, mode, _, _):
                if mode == .guardProxy {
                    Button("接管恢复守护") {
                        Task {
                            await guardEngine.resumeCrashedGuard()
                            await model.scan(online: false)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
                Button("恢复原有设置") {
                    Task {
                        await guardEngine.stopProtection()
                        await model.scan(online: false)
                    }
                }
            }
        }
        .disabled(guardEngine.busy)
    }

    // MARK: - Connection Audit Page

    private var auditView: some View {
        let stats = guardEngine.auditStats
        let filtered = guardEngine.recentAuditEntries.filter { entry in
            if model.auditClaudeOnly && !entry.isClaudeDomain { return false }
            switch model.auditFilter {
            case .all: break
            case .allowed: if entry.decision != .allowed { return false }
            case .blocked: if entry.decision != .blocked && entry.decision != .rejectedLoopback { return false }
            case .errors: if entry.decision != .upstreamError { return false }
            }
            let kw = model.auditSearch.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if !kw.isEmpty {
                let hay = "\(entry.host):\(entry.port) \(entry.exitIP ?? "") \(entry.exitCountry ?? "") \(entry.reason ?? "")".lowercased()
                if !hay.contains(kw) { return false }
            }
            return true
        }

        return VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 4) {
                    sectionTitle("连接审计日志（48 小时）", icon: "list.bullet.rectangle.portrait")
                    Text("仅记录经由本地熔断网关的域名、决策、出口 IP 与流量字节数，绝不记录 API Key、请求头或正文内容")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if let msg = model.exportMessage {
                    Text(msg).font(.caption).foregroundStyle(.teal)
                }
                Button("导出 CSV") { Task { await model.exportAudit(asCSV: true) } }
                    .disabled(stats.total == 0)
                Button("导出 JSON") { Task { await model.exportAudit(asCSV: false) } }
                    .disabled(stats.total == 0)
                if stats.total > 0 {
                    Button("清空日志") { model.confirmClearAudit = true }
                }
            }

            HStack(spacing: 12) {
                kpiBox("总连接记录", value: "\(stats.total)", accent: .teal)
                kpiBox("已放行", value: "\(stats.allowed)", accent: .teal)
                kpiBox("已熔断拦截", value: "\(stats.blocked)", accent: stats.blocked > 0 ? .red : .secondary)
                kpiBox("上游异常", value: "\(stats.upstreamErrors)", accent: stats.upstreamErrors > 0 ? .orange : .secondary)
                kpiBox("当前活跃隧道", value: "\(guardEngine.activeTunnels)", accent: guardEngine.activeTunnels > 0 ? .teal : .secondary)
            }

            HStack(spacing: 12) {
                Picker("状态筛选", selection: $model.auditFilter) {
                    ForEach(AuditFilter.allCases) { f in Text(f.rawValue).tag(f) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 300)

                Toggle("仅看 Claude 域名", isOn: $model.auditClaudeOnly)
                    .toggleStyle(.checkbox)

                Spacer()

                TextField("搜索域名 / IP / 原因…", text: $model.auditSearch)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
            }

            if filtered.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text(stats.total == 0 ? "暂无连接审计记录" : "无符合筛选条件的记录")
                        .font(.title3.weight(.semibold))
                    Text(stats.total == 0
                         ? "启用「熔断守卫模式」并重启 Claude Code 后，所有经本地守护端口的请求元数据都会实时记录在这里。"
                         : "可以清空搜索关键词或切换筛选状态。")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 120, alignment: .leading)
                .padding(.horizontal, 20)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
                .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 10) {
                        Text("时间").frame(width: 82, alignment: .leading)
                        Text("目标主机").frame(maxWidth: .infinity, alignment: .leading)
                        Text("决策").frame(width: 72, alignment: .leading)
                        Text("出口 IP / 地区").frame(width: 155, alignment: .leading)
                        Text("流量 ↑ / ↓").frame(width: 115, alignment: .trailing)
                        Text("耗时").frame(width: 66, alignment: .trailing)
                    }
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 10)

                    ForEach(filtered.prefix(120)) { entry in
                        Divider()
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(alignment: .center, spacing: 10) {
                                Text(entry.startedAt.formatted(date: .omitted, time: .standard))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 82, alignment: .leading)
                                HStack(spacing: 6) {
                                    Text(verbatim: "\(entry.host):\(String(entry.port))")
                                        .font(.system(.callout, design: .monospaced))
                                        .textSelection(.enabled)
                                        .lineLimit(1)
                                    if entry.isClaudeDomain {
                                        Text("Claude")
                                            .font(.caption2.weight(.semibold))
                                            .foregroundStyle(.teal)
                                            .padding(.horizontal, 5)
                                            .padding(.vertical, 1)
                                            .background(.teal.opacity(0.12), in: Capsule())
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                Text(entry.decision.label)
                                    .font(.caption.weight(.medium))
                                    .foregroundStyle(decisionColor(entry.decision))
                                    .frame(width: 72, alignment: .leading)
                                Text(formatExit(entry))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .frame(width: 155, alignment: .leading)
                                Text("\(formatBytes(entry.bytesUp)) / \(formatBytes(entry.bytesDown))")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 115, alignment: .trailing)
                                Text(verbatim: entry.durationMs.map { "\(String($0))ms" } ?? "—")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 66, alignment: .trailing)
                            }
                            if let reason = entry.reason, !reason.isEmpty {
                                Text(reason)
                                    .font(.caption)
                                    .foregroundStyle(decisionColor(entry.decision))
                                    .padding(.leading, 92)
                            }
                        }
                        .padding(.vertical, 8)
                    }
                }
                .padding(.horizontal, 14)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
                .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
            }
        }
    }

    private func decisionColor(_ decision: ConnectionDecision) -> Color {
        switch decision {
        case .allowed: .teal
        case .blocked, .rejectedLoopback: .red
        case .upstreamError: .orange
        }
    }

    private func formatExit(_ entry: ConnectionAuditEntry) -> String {
        if let ip = entry.exitIP, let cc = entry.exitCountry {
            return "\(cc) · \(ip)"
        }
        return entry.exitIP ?? entry.exitCountry ?? "—"
    }

    private func formatBytes(_ count: Int64) -> String {
        if count < 1024 { return "\(count)B" }
        if count < 1024 * 1024 { return String(format: "%.1fK", Double(count) / 1024.0) }
        return String(format: "%.1fM", Double(count) / (1024.0 * 1024.0))
    }

    // MARK: - Diagnostic Cards

    private func highlightProbe(_ id: ReadingID, snapshot: Snapshot) -> some View {
        let reading = snapshot.reading(id)
        let color = severityColor(reading)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: severityIcon(reading))
                    .foregroundStyle(color)
                    .accessibilityHidden(true)
                Text(id.title)
                    .font(.subheadline.weight(.semibold))
            }
            Text(reading.value)
                .font(.system(size: 15, weight: .semibold, design: reading.state == .response ? .monospaced : .default))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if let detail = reading.detail, !detail.isEmpty {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text(id.source)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 92, alignment: .topLeading)
        .padding(13)
        .background(color.opacity(0.06), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(color.opacity(0.2)) }
    }

    private func groupCard(_ title: String, icon: String, ids: [ReadingID], snapshot: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionTitle(title, icon: icon)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(ids) { id in
                    if id != ids.first { Divider() }
                    let reading = snapshot.reading(id)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Image(systemName: severityIcon(reading))
                                .font(.caption)
                                .foregroundStyle(severityColor(reading))
                                .accessibilityHidden(true)
                            Text(id.title)
                                .font(.subheadline.weight(.medium))
                                .foregroundStyle(.secondary)
                        }
                        Text(reading.value)
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        if let detail = reading.detail, !detail.isEmpty {
                            Text(detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 10)
                }
            }
            .padding(.horizontal, 14)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
            .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: - Multi-Snapshot Baseline Comparison Page

    @ViewBuilder
    private func comparison(_ current: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    sectionTitle("多快照基线对比", icon: "square.split.2x1")
                    Text("最多保存 10 份命名快照，随时自由对比「修复前 / 开防护后 / 切节点后」的完整差异")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                TextField("快照标签（选填，如：修 DNS 前）", text: $model.snapshotLabelDraft)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 210)
                Button("保存当前为快照") { model.saveCurrentAsSnapshot() }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.scanning)
                if !model.savedSnapshots.isEmpty {
                    Button("清空全部") { model.confirmClearBaselines = true }
                }
            }

            if let issue = model.baselineIssue {
                Label(issue, systemImage: "exclamationmark.circle")
                    .foregroundStyle(.orange)
            }

            if let baselineEntry = model.selectedBaseline {
                let baseline = baselineEntry.snapshot
                HStack(spacing: 12) {
                    Text("选择对比基线")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Picker("对比基线", selection: Binding(
                        get: { model.selectedBaselineID ?? baselineEntry.id },
                        set: { model.selectedBaselineID = $0 }
                    )) {
                        ForEach(model.savedSnapshots) { item in
                            Text("\(item.label)（\(item.snapshot.capturedAt.formatted(date: .abbreviated, time: .shortened))）")
                                .tag(item.id)
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: 420)

                    Button("删除此快照") {
                        model.deleteSnapshot(baselineEntry.id)
                    }
                    .controlSize(.small)

                    Spacer()

                    let changed = ReadingID.allCases.filter {
                        Comparison(baseline.reading($0), current.reading($0)) == .changed
                    }
                    Text("\(changed.count) 项变化")
                        .font(.callout.weight(.medium))
                    Toggle("仅显示变化项", isOn: $model.changesOnly)
                        .toggleStyle(.checkbox)
                }

                let changed = ReadingID.allCases.filter {
                    Comparison(baseline.reading($0), current.reading($0)) == .changed
                }
                let visible = model.changesOnly ? changed : ReadingID.allCases
                if visible.isEmpty {
                    Text("两次已采样的项目完全一致。")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, minHeight: 145)
                } else {
                    comparisonTable(visible, baseline: baseline, current: current)
                }
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    Text("还没有保存基线快照")
                        .font(.title3.weight(.semibold))
                    Text("输入可选标签并点击「保存当前为快照」，调整网络/规则或开启防护后再检测即可逐项对比。")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 108, alignment: .leading)
                .padding(.horizontal, 20)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
                .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
            }
        }
    }

    private func comparisonTable(_ ids: [ReadingID], baseline: Snapshot, current: Snapshot) -> some View {
        VStack(spacing: 0) {
            comparisonRow("项目", before: "基线（\(baseline.probeRouteDescription)）", after: "当前（\(current.probeRouteDescription)）", status: "状态")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(ids) { id in
                let previous = baseline.reading(id)
                let latest = current.reading(id)
                let result = Comparison(previous, latest)
                Divider()
                comparisonRow(id.title, before: previous.value, after: latest.value,
                              status: comparisonLabel(result), changed: result == .changed)
            }
        }
        .padding(.horizontal, 14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    private func comparisonRow(
        _ title: String, before: String, after: String, status: String, changed: Bool = false
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(title).frame(width: 145, alignment: .leading)
            Text(before).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text(after).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text(status)
                .foregroundStyle(changed ? Color.teal : Color.secondary)
                .frame(width: 56, alignment: .leading)
        }
        .padding(.vertical, 9)
    }

    private func comparisonLabel(_ result: Comparison) -> String {
        switch result {
        case .changed: "有变化"
        case .same: "一致"
        case .incomplete: "缺测"
        }
    }

    // MARK: - 48h Exit History Page

    private var historyView: some View {
        let summary = model.historySummary
        return VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    sectionTitle("48 小时出口漂移追踪", icon: "clock.arrow.circlepath")
                    Text("自动记录每次联网实测与后台守卫巡检的公网出口 IP、归属地区与 ASN，识别静默跨国跳变")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if summary.sampleCount > 0 {
                    Button("清空历史") { model.confirmClearHistory = true }
                }
            }

            HStack(spacing: 12) {
                kpiBox("48h 采样次数", value: "\(summary.sampleCount)", accent: .teal)
                kpiBox("独立 IP 数", value: "\(summary.uniqueIPCount)", accent: summary.uniqueIPCount > 2 ? .orange : .teal)
                kpiBox("IP 变更次数", value: "\(summary.ipChanges)", accent: summary.ipChanges > 0 ? .orange : .teal)
                kpiBox(
                    "跨国跳变次数",
                    value: "\(summary.countryChanges)",
                    accent: (summary.countryChanges >= 2 || summary.guardedCountryChanges > 0) ? .red : (summary.countryChanges == 1 ? .orange : .teal)
                )
            }

            if summary.recentSamples.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("尚无出口历史记录")
                        .font(.title3.weight(.semibold))
                    Text("点击右上角「联网检测」或开启熔断守卫后，将自动记录公网出口与地区变化。")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 110, alignment: .leading)
                .padding(.horizontal, 20)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
                .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Text("时间").frame(width: 150, alignment: .leading)
                        Text("出口 IP").frame(width: 145, alignment: .leading)
                        Text("地区 / 合规").frame(width: 140, alignment: .leading)
                        Text("ASN / 运营商").frame(maxWidth: .infinity, alignment: .leading)
                        Text("探测路径").frame(width: 170, alignment: .leading)
                    }
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 10)

                    ForEach(summary.recentSamples) { sample in
                        Divider()
                        let support = ClaudeRegions.support(for: sample.countryCode)
                        let regionColor: Color = support == .supported ? .teal : (support == .unsupported ? .red : .secondary)
                        let asnOrg = [sample.asn.map { "AS\($0)" }, sample.org].compactMap { $0 }.joined(separator: " · ")
                        HStack(alignment: .top, spacing: 12) {
                            Text(sample.capturedAt.formatted(date: .abbreviated, time: .standard))
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .frame(width: 150, alignment: .leading)
                            Text(sample.ip)
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(width: 145, alignment: .leading)
                            Text(ClaudeRegions.displayName(for: sample.countryCode))
                                .font(.callout.weight(.medium))
                                .foregroundStyle(regionColor)
                                .frame(width: 140, alignment: .leading)
                            Text(asnOrg.isEmpty ? sample.networkKind.label : asnOrg)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            Text(sample.probePath)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .frame(width: 170, alignment: .leading)
                        }
                        .padding(.vertical, 9)
                    }
                }
                .padding(.horizontal, 14)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
                .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
            }
        }
    }

    private func kpiBox(_ title: String, value: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(size: 22, weight: .semibold, design: .monospaced)).foregroundStyle(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(13)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - Styling Helpers

    private func sectionTitle(_ title: String, icon: String) -> some View {
        Label(title, systemImage: icon)
            .font(.headline)
            .accessibilityAddTraits(.isHeader)
    }

    private func verdictIcon(_ level: EnvironmentVerdict.Level) -> String {
        switch level {
        case .healthy: "checkmark.seal.fill"
        case .caution: "exclamationmark.triangle.fill"
        case .risk: "xmark.octagon.fill"
        case .offlineOnly: "info.circle.fill"
        }
    }

    private func verdictColor(_ level: EnvironmentVerdict.Level) -> Color {
        switch level {
        case .healthy: .teal
        case .caution: .orange
        case .risk: .red
        case .offlineOnly: .secondary
        }
    }

    private func severityIcon(_ reading: Reading) -> String {
        if reading.state == .pending { return "clock" }
        switch reading.severity {
        case .ok: return "checkmark.circle.fill"
        case .caution: return "exclamationmark.triangle.fill"
        case .danger: return "xmark.octagon.fill"
        case .neutral: return reading.state == .unavailable ? "questionmark.circle" : "circle.fill"
        }
    }

    private func severityColor(_ reading: Reading) -> Color {
        if reading.state == .pending { return .secondary }
        switch reading.severity {
        case .ok: return .teal
        case .caution: return .orange
        case .danger: return .red
        case .neutral: return .secondary
        }
    }
}
