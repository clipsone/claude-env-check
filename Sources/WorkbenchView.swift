import AppKit
import SwiftUI

@MainActor
final class WorkbenchController: ObservableObject {
    private static let updateRepoKey = "githubUpdateRepo.v1"

    @Published private(set) var browsers: [DiscoveredBrowser] = []
    @Published var selectedBrowserID: String = ""
    @Published var browserStartURL: String = "https://claude.ai"
    @Published private(set) var runningBrowserName: String?
    @Published private(set) var selectedProfileBytes: Int64 = 0
    @Published private(set) var browserNote: String?
    @Published private(set) var browserIssue: String?

    @Published private(set) var desktopInventory: ClaudeDesktopInventory?
    @Published var selectedCleanupIDs: Set<String> = []
    @Published var desktopUseIsolatedProfile: Bool = false
    @Published var confirmTrashDesktopItems: Bool = false
    @Published var confirmTrashBrowserProfile: Bool = false
    @Published private(set) var desktopBusy: Bool = false
    @Published private(set) var desktopNote: String?
    @Published private(set) var desktopIssue: String?

    @Published var updateRepoSlug: String {
        didSet {
            UserDefaults.standard.set(updateRepoSlug, forKey: Self.updateRepoKey)
        }
    }
    @Published private(set) var checkingUpdate: Bool = false
    @Published private(set) var updateResult: ReleaseCheckResult?
    @Published private(set) var updateError: String?

    @Published private(set) var shellGuardStatus: TerminalGuardStatus = .notInstalled
    @Published private(set) var shellGuardNote: String?
    @Published private(set) var shellGuardError: String?
    @Published var copiedShellAlias: Bool = false

    private var trackedBrowserProcess: Process?

    init() {
        let saved = UserDefaults.standard.string(forKey: Self.updateRepoKey)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        self.updateRepoSlug = saved.isEmpty ? "clipsone/claude-env-check" : saved
        self.shellGuardStatus = TerminalShellGuard.inspectStatus()
    }

    var selectedBrowser: DiscoveredBrowser? {
        browsers.first(where: { $0.id == selectedBrowserID }) ?? browsers.first
    }

    var isTrackedBrowserRunning: Bool {
        if let proc = trackedBrowserProcess, proc.isRunning {
            return true
        }
        return false
    }

    func refreshAll() async {
        refreshBrowsers()
        refreshShellGuard()
        await refreshDesktop()
    }

    func refreshShellGuard() {
        shellGuardStatus = TerminalShellGuard.inspectStatus()
    }

    func installShellGuard() {
        shellGuardError = nil
        shellGuardNote = nil
        do {
            let url = try TerminalShellGuard.install()
            refreshShellGuard()
            shellGuardNote = "已安装终端防漏安全壳至 \(url.path)。运行 claude-safe 或配置 alias 后，每次启动 Claude Code 前都会先核验本地熔断守卫。"
        } catch {
            shellGuardError = error.localizedDescription
        }
    }

    func uninstallShellGuard() {
        shellGuardError = nil
        shellGuardNote = nil
        do {
            try TerminalShellGuard.uninstall()
            refreshShellGuard()
            shellGuardNote = "已卸载 ~/.local/bin/claude-safe。"
        } catch {
            shellGuardError = error.localizedDescription
        }
    }

    func copyShellAliasSnippet() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(TerminalShellGuard.shellAliasSnippet(), forType: .string)
        copiedShellAlias = true
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            copiedShellAlias = false
        }
    }

    func refreshBrowsers() {
        browsers = IsolatedBrowserLauncher.discoverBrowsers()
        if selectedBrowserID.isEmpty || !browsers.contains(where: { $0.id == selectedBrowserID }) {
            selectedBrowserID = browsers.first?.id ?? ""
        }
        if let proc = trackedBrowserProcess, !proc.isRunning {
            trackedBrowserProcess = nil
            runningBrowserName = nil
        }
        refreshSelectedProfileSize()
    }

    func refreshSelectedProfileSize() {
        guard let browser = selectedBrowser else {
            selectedProfileBytes = 0
            return
        }
        selectedProfileBytes = IsolatedBrowserLauncher.profileSizeBytes(browserID: browser.id)
    }

    func launchIsolatedBrowser(proxyPort: Int?, countryCode: String?, geoTimeZone: String?) {
        browserIssue = nil
        browserNote = nil
        guard let browser = selectedBrowser else {
            browserIssue = WorkbenchError.browserNotFound.localizedDescription
            return
        }
        if let existing = trackedBrowserProcess, existing.isRunning {
            browserNote = "隔离浏览器（\(runningBrowserName ?? browser.name)）已在运行中。"
            return
        }
        let spec = IsolatedBrowserLauncher.buildLaunchSpec(
            browser: browser,
            proxyPort: proxyPort,
            countryCode: countryCode,
            geoTimeZone: geoTimeZone,
            startURL: browserStartURL
        )
        do {
            let proc = try IsolatedBrowserLauncher.launch(spec: spec)
            trackedBrowserProcess = proc
            runningBrowserName = browser.name
            proc.terminationHandler = { [weak self] _ in
                Task { @MainActor in
                    self?.trackedBrowserProcess = nil
                    self?.runningBrowserName = nil
                    self?.refreshSelectedProfileSize()
                }
            }
            var flagsDesc: [String] = ["禁用 QUIC", "防 WebRTC 泄漏", "无提示条"]
            if let port = spec.proxyPort { flagsDesc.append("代理 127.0.0.1:\(String(port))") }
            if let tz = spec.timeZone { flagsDesc.append("进程 TZ=\(tz)") }
            if let lang = spec.language { flagsDesc.append("语言 \(lang)") }
            browserNote = "已启动隔离 \(browser.name)（\(flagsDesc.joined(separator: " · "))，未复制日常书签或 Cookie）。"
            refreshSelectedProfileSize()
        } catch {
            browserIssue = error.localizedDescription
        }
    }

    func closeTrackedBrowser() {
        guard let proc = trackedBrowserProcess, proc.isRunning else {
            trackedBrowserProcess = nil
            runningBrowserName = nil
            return
        }
        proc.terminate()
        browserNote = "已发送退出信号给隔离浏览器。"
    }

    func trashSelectedBrowserProfile() {
        browserIssue = nil
        browserNote = nil
        guard !isTrackedBrowserRunning else {
            browserIssue = "请先关闭正在运行的隔离浏览器，再清理其配置目录。"
            return
        }
        guard let browser = selectedBrowser else { return }
        do {
            try IsolatedBrowserLauncher.trashProfile(browserID: browser.id)
            refreshSelectedProfileSize()
            browserNote = "已将 \(browser.name) 隔离工作台目录安全移入系统废纸篓。"
        } catch {
            browserIssue = error.localizedDescription
        }
    }

    // MARK: - Claude Desktop Management

    func refreshDesktop() async {
        desktopBusy = true
        defer { desktopBusy = false }
        let inv = await ClaudeDesktopManager.inspect()
        desktopInventory = inv
        let existingIDs = Set(inv.existingItems.map(\.id))
        selectedCleanupIDs = selectedCleanupIDs.intersection(existingIDs)
    }

    func selectCacheItemsOnly() {
        guard let inv = desktopInventory else { return }
        selectedCleanupIDs = Set(inv.existingItems.filter { $0.category == .cacheAndCookies }.map(\.id))
    }

    func selectAllDesktopItems() {
        guard let inv = desktopInventory else { return }
        selectedCleanupIDs = Set(inv.existingItems.map(\.id))
    }

    func quitRunningDesktop() async {
        desktopIssue = nil
        _ = ClaudeDesktopManager.terminateRunningDesktop()
        try? await Task.sleep(nanoseconds: 800_000_000)
        await refreshDesktop()
        if desktopInventory?.running == false {
            desktopNote = "已退出 Claude Desktop。"
        } else {
            desktopIssue = "已发送退出请求，请确认 Claude Desktop 是否已完全关闭。"
        }
    }

    func trashSelectedDesktopItems() async {
        guard let inv = desktopInventory else { return }
        let chosen = inv.existingItems.filter { selectedCleanupIDs.contains($0.id) }
        guard !chosen.isEmpty else { return }
        desktopBusy = true
        desktopIssue = nil
        desktopNote = nil
        defer { desktopBusy = false }
        do {
            let count = try await ClaudeDesktopManager.trashItems(chosen)
            selectedCleanupIDs.removeAll()
            desktopNote = "已将 \(count) 项 Claude Desktop 数据安全移入系统废纸篓（未触碰 ~/.claude）。"
            await refreshDesktop()
        } catch {
            desktopIssue = error.localizedDescription
        }
    }

    func launchDesktopAligned(proxyPort: Int?, countryCode: String?, geoTimeZone: String?) async {
        desktopIssue = nil
        desktopNote = nil
        await refreshDesktop()
        guard let inv = desktopInventory else { return }
        do {
            _ = try ClaudeDesktopManager.launchAligned(
                inventory: inv,
                proxyPort: proxyPort,
                countryCode: countryCode,
                geoTimeZone: geoTimeZone,
                useIsolatedProfile: desktopUseIsolatedProfile
            )
            var notes: [String] = ["禁 QUIC", "防 WebRTC"]
            if let port = proxyPort { notes.append("全链路代理 127.0.0.1:\(String(port))") }
            if let cc = countryCode {
                let p = ClaudeRegions.recommendedProcessLocale(countryCode: cc, geoTimeZone: geoTimeZone)
                notes.append("进程 TZ=\(p.timeZone)")
                notes.append("语言 \(IsolatedBrowserLauncher.bcp47Tag(fromPOSIX: p.lang))")
            }
            if desktopUseIsolatedProfile { notes.append("独立 Profile") }
            desktopNote = "已启动对齐环境的 Claude Desktop（\(notes.joined(separator: " · "))）。"
            try? await Task.sleep(nanoseconds: 600_000_000)
            await refreshDesktop()
        } catch {
            desktopIssue = error.localizedDescription
        }
    }

    // MARK: - Passive Update Check

    func checkUpdates(proxyPort: Int?) async {
        guard !checkingUpdate else { return }
        checkingUpdate = true
        updateError = nil
        defer { checkingUpdate = false }
        do {
            updateResult = try await UpdateChecker.checkLatestRelease(
                repoSlug: updateRepoSlug,
                proxyPort: proxyPort
            )
        } catch {
            updateResult = nil
            updateError = error.localizedDescription
        }
    }
}

struct WorkbenchView: View {
    @ObservedObject var workbench: WorkbenchController
    @ObservedObject var guardEngine: ProtectionGuardEngine
    let activeProxyPort: Int?
    let exitCountryCode: String?
    let exitTimeZone: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Label("Claude 全家桶安全工作台（macOS 专属）", systemImage: "macwindow.on.rectangle")
                        .font(.headline)
                    Text("隔离浏览器启动、Claude Desktop 对齐启动与废纸篓安全清理，全程零 Root、零全局时区篡改、绝不复制日常书签")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await workbench.refreshAll() }
                } label: {
                    Label("刷新状态", systemImage: "arrow.clockwise")
                }
            }

            isolatedBrowserCard
            claudeDesktopCard
            terminalShellGuardCard
            loginItemAndAutoGuardCard
            releaseUpdateCard
        }
        .confirmationDialog("将选中的 Claude Desktop 数据移入废纸篓？", isPresented: $workbench.confirmTrashDesktopItems, titleVisibility: .visible) {
            Button("移入废纸篓（可还原）", role: .destructive) {
                Task { await workbench.trashSelectedDesktopItems() }
            }
        }
        .confirmationDialog("将隔离浏览器工作台目录移入废纸篓？", isPresented: $workbench.confirmTrashBrowserProfile, titleVisibility: .visible) {
            Button("移入废纸篓", role: .destructive) {
                workbench.trashSelectedBrowserProfile()
            }
        }
    }

    // MARK: - 1. Isolated Browser Workbench

    private var isolatedBrowserCard: some View {
        let effectivePort = guardEngine.guardPort ?? activeProxyPort
        let country = guardEngine.lastVerifiedCountry ?? exitCountryCode

        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("隔离浏览器工作台（Web 版 claude.ai）", systemImage: "safari")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                if workbench.isTrackedBrowserRunning {
                    Text("运行中 · \(workbench.runningBrowserName ?? "")")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.teal)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(.teal.opacity(0.12), in: Capsule())
                }
            }

            Text("以独立 --user-data-dir 启动本机 Chromium 浏览器：自动注入 --disable-quic、WebRTC 防直连 UDP 泄漏、HTTP 代理远端解析及进程级 TZ + Accept-Language 对齐（不弹不受支持标记横幅，绝不碰日常 Chrome 数据或复制书签）。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if workbench.browsers.isEmpty {
                Text("未检测到已安装的 Google Chrome / Brave / Microsoft Edge / Vivaldi。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                HStack(spacing: 12) {
                    Picker("浏览器", selection: Binding(
                        get: { workbench.selectedBrowserID },
                        set: {
                            workbench.selectedBrowserID = $0
                            workbench.refreshSelectedProfileSize()
                        }
                    )) {
                        ForEach(workbench.browsers) { b in
                            Text("\(b.name)\(b.version.map { " (\($0))" } ?? "")").tag(b.id)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 220)

                    TextField("起始地址", text: $workbench.browserStartURL)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 220)

                    Spacer()

                    if workbench.isTrackedBrowserRunning {
                        Button("关闭隔离浏览器") {
                            workbench.closeTrackedBrowser()
                        }
                    } else {
                        Button {
                            workbench.launchIsolatedBrowser(
                                proxyPort: effectivePort,
                                countryCode: country,
                                geoTimeZone: exitTimeZone
                            )
                        } label: {
                            Label("启动隔离浏览器", systemImage: "play.fill")
                        }
                        .buttonStyle(.borderedProminent)
                    }

                    if workbench.selectedProfileBytes > 0 {
                        Button("清空工作台 (\(formatBytes(workbench.selectedProfileBytes)))") {
                            workbench.confirmTrashBrowserProfile = true
                        }
                        .disabled(workbench.isTrackedBrowserRunning)
                    }
                }

                HStack(spacing: 14) {
                    Label(effectivePort.map { "将经 127.0.0.1:\(String($0)) 代理（HTTP CONNECT 远端解析）" } ?? "未检测到代理端口（将直连系统网络）",
                          systemImage: "network")
                    if let country {
                        let p = ClaudeRegions.recommendedProcessLocale(countryCode: country, geoTimeZone: exitTimeZone)
                        Label("进程 TZ=\(p.timeZone) · 语言 \(IsolatedBrowserLauncher.bcp47Tag(fromPOSIX: p.lang))",
                              systemImage: "clock")
                    } else {
                        Label("先做一次联网检测或开启守卫可自动对齐出口时区/语言", systemImage: "clock")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            if let issue = workbench.browserIssue {
                Label(issue, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if let note = workbench.browserNote {
                Text(note).font(.callout).foregroundStyle(.teal)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - 2. macOS Claude Desktop Alignment & Safe Trash Cleanup

    private var claudeDesktopCard: some View {
        let effectivePort = guardEngine.guardPort ?? activeProxyPort
        let country = guardEngine.lastVerifiedCountry ?? exitCountryCode

        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Claude Desktop（macOS 专属对齐启动与安全清理）", systemImage: "desktopcomputer")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                if let inv = workbench.desktopInventory {
                    if inv.installed {
                        Text("\(inv.version ?? "已安装") · \(inv.running ? "运行中" : "未运行") · 数据 \(formatBytes(inv.totalBytes))")
                            .font(.caption)
                            .foregroundStyle(inv.running ? .teal : .secondary)
                    } else {
                        Text("未安装 Claude Desktop").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            if let inv = workbench.desktopInventory {
                if inv.installed {
                    HStack(spacing: 12) {
                        Toggle("使用独立隔离数据目录（保留原登录状态）", isOn: $workbench.desktopUseIsolatedProfile)
                            .toggleStyle(.checkbox)
                            .font(.callout)
                        Spacer()
                        if inv.running {
                            Button("先退出 Claude Desktop") {
                                Task { await workbench.quitRunningDesktop() }
                            }
                        }
                        Button {
                            Task {
                                await workbench.launchDesktopAligned(
                                    proxyPort: effectivePort,
                                    countryCode: country,
                                    geoTimeZone: exitTimeZone
                                )
                            }
                        } label: {
                            Label("对齐环境启动 Desktop", systemImage: "arrow.up.forward.app")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(workbench.desktopBusy)
                    }
                }

                Divider()

                HStack {
                    Text("安全清理项（按项勾选，校验防符号链接后仅移入系统废纸篓，绝不触碰 ~/.claude）")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("仅选缓存/Cookie") { workbench.selectCacheItemsOnly() }
                        .controlSize(.small)
                        .disabled(inv.existingItems.isEmpty)
                    Button("全选") { workbench.selectAllDesktopItems() }
                        .controlSize(.small)
                        .disabled(inv.existingItems.isEmpty)
                    Button("移入废纸篓 (\(workbench.selectedCleanupIDs.count))") {
                        workbench.confirmTrashDesktopItems = true
                    }
                    .controlSize(.small)
                    .tint(.red)
                    .disabled(workbench.selectedCleanupIDs.isEmpty || inv.running || workbench.desktopBusy)
                }

                if inv.existingItems.isEmpty {
                    Text("当前未发现 Claude Desktop 的本机缓存或数据目录。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 4)
                } else {
                    VStack(spacing: 0) {
                        ForEach(inv.existingItems) { item in
                            if item.id != inv.existingItems.first?.id { Divider() }
                            HStack(spacing: 10) {
                                Toggle("", isOn: Binding(
                                    get: { workbench.selectedCleanupIDs.contains(item.id) },
                                    set: { checked in
                                        if checked { workbench.selectedCleanupIDs.insert(item.id) }
                                        else { workbench.selectedCleanupIDs.remove(item.id) }
                                    }
                                ))
                                .toggleStyle(.checkbox)
                                .labelsHidden()
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 6) {
                                        Text(item.title).font(.callout.weight(.medium))
                                        Text(item.category.label)
                                            .font(.caption2)
                                            .foregroundStyle(item.category == .appDataAndPrefs ? .orange : .secondary)
                                            .padding(.horizontal, 5)
                                            .padding(.vertical, 1)
                                            .background(.quaternary.opacity(0.6), in: Capsule())
                                    }
                                    Text(item.relativePath)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(formatBytes(item.sizeBytes))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 6)
                        }
                    }
                }
            } else {
                ProgressView("正在扫描 Claude Desktop 状态…")
            }

            if let issue = workbench.desktopIssue {
                Label(issue, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if let note = workbench.desktopNote {
                Text(note).font(.callout).foregroundStyle(.teal)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - 3. Terminal Anti-Leak Shell Guard (claude-safe)

    private var terminalShellGuardCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label("终端防漏安全壳（claude-safe）", systemImage: "terminal.fill")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                switch workbench.shellGuardStatus {
                case .installed:
                    Text("已安装")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.teal)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(.teal.opacity(0.12), in: Capsule())
                case .notInstalled:
                    Text("未安装")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                case .foreignFileExists:
                    Text("存在外部同名文件")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            Text("在 ~/.local/bin/claude-safe 安装轻量校验壳（< 50ms 本地探测 /__claude_guard_health，零外网流量）：每次启动 Claude Code 前自动确认本地熔断守卫活着且未熔断，防止忘开守卫裸连出去。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 10) {
                switch workbench.shellGuardStatus {
                case .notInstalled:
                    Button {
                        workbench.installShellGuard()
                    } label: {
                        Label("一键安装 claude-safe", systemImage: "bolt.shield")
                    }
                    .buttonStyle(.borderedProminent)
                case .installed:
                    Button("更新脚本") {
                        workbench.installShellGuard()
                    }
                    Button("卸载安全壳", role: .destructive) {
                        workbench.uninstallShellGuard()
                    }
                case .foreignFileExists(let path):
                    Text("已有非本工具文件：\(path)")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }

                Spacer()

                Button {
                    workbench.copyShellAliasSnippet()
                } label: {
                    Label(workbench.copiedShellAlias ? "已复制 ~/.zshrc 别名" : "复制 alias claude='claude-safe'",
                          systemImage: workbench.copiedShellAlias ? "checkmark" : "doc.on.doc")
                }
            }

            Text(verbatim: TerminalShellGuard.shellAliasSnippet())
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                .overlay { RoundedRectangle(cornerRadius: 7).strokeBorder(.quaternary) }

            if let err = workbench.shellGuardError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if let note = workbench.shellGuardNote {
                Text(note).font(.callout).foregroundStyle(.teal)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - 4. Login Item & Auto-Guard

    private var loginItemAndAutoGuardCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label("开机静默常驻与自动护卫（SMAppService · 零 Root）", systemImage: "power.circle")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text(guardEngine.loginItemState.label)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(guardEngine.loginItemState.isEnabled ? .teal : .secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background((guardEngine.loginItemState.isEnabled ? Color.teal : Color.secondary).opacity(0.12), in: Capsule())
            }

            Text("使用 macOS 原生 SMAppService 登记用户级登录项（绝不装 Root 守护进程）。开启自动护卫后，开机启动时将自动等待代理客户端就绪（最多 20 秒）并自动拉起本地熔断守卫。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 16) {
                Toggle("开机自动启动并常驻菜单栏", isOn: Binding(
                    get: { guardEngine.loginItemState.isEnabled },
                    set: { guardEngine.setLoginItemEnabled($0) }
                ))
                .toggleStyle(.checkbox)

                Toggle("启动后自动等待代理就绪并开启熔断守卫", isOn: $guardEngine.autoStartGuardOnLaunch)
                    .toggleStyle(.checkbox)

                Spacer()

                Button("刷新状态") {
                    guardEngine.refreshLoginItemState()
                }
                .controlSize(.small)
            }
            .font(.callout)

            if let err = guardEngine.loginItemError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if let note = guardEngine.loginItemNote {
                Text(note).font(.callout).foregroundStyle(.teal)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - 5. Passive GitHub Releases Update Checker

    private var releaseUpdateCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("版本与被动式更新检查", systemImage: "arrow.down.circle")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text("当前版本 v\(UpdateChecker.currentAppVersion)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 10) {
                TextField("GitHub 仓库（owner/repo，如 yourname/claude-env-check）", text: $workbench.updateRepoSlug)
                    .textFieldStyle(.roundedBorder)
                Button {
                    Task { await workbench.checkUpdates(proxyPort: guardEngine.guardPort ?? activeProxyPort) }
                } label: {
                    Label(workbench.checkingUpdate ? "检查中…" : "检查更新", systemImage: "magnifyingglass")
                }
                .disabled(workbench.checkingUpdate || workbench.updateRepoSlug.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            Text("纯被动只读检查 GitHub Releases 最新稳定版（绝不后台静默下载或自动执行安装包）。")
                .font(.caption)
                .foregroundStyle(.secondary)

            if let err = workbench.updateError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if let res = workbench.updateResult {
                switch res.status {
                case .upToDate:
                    Label("已是最新版本（v\(res.currentVersion)）。", systemImage: "checkmark.circle.fill")
                        .font(.callout)
                        .foregroundStyle(.teal)
                case .noReleases:
                    Text("仓库 \(res.repoSlug) 暂无正式 Release 发布。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                case let .updateAvailable(latest, url, assetName, _):
                    HStack {
                        Label("发现新版本 v\(latest.description)\(assetName.map { "（\($0)）" } ?? "")", systemImage: "sparkles")
                            .font(.callout.weight(.medium))
                            .foregroundStyle(.teal)
                        Spacer()
                        Button("在浏览器打开 Release 页面") {
                            NSWorkspace.shared.open(url)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                }
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    private func formatBytes(_ count: Int64) -> String {
        if count < 1024 { return "\(count) B" }
        if count < 1024 * 1024 { return String(format: "%.1f KB", Double(count) / 1024.0) }
        return String(format: "%.1f MB", Double(count) / (1024.0 * 1024.0))
    }
}
