import AppKit
import SwiftUI

struct ClashSymbiosisView: View {
    @ObservedObject var guardEngine: ProtectionGuardEngine

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 4) {
                    Label("代理客户端共生与 Clash / Mihomo 深度协同", systemImage: "point.3.connected.trianglepath.dotted")
                        .font(.headline)
                    Text("自动发现本机代理客户端（独立探测 HTTP/SOCKS5 双协议）并直连 Clash 控制器监控路由漂移与直连违规，全程免 Root、零冲突")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if guardEngine.clashBusy {
                    ProgressView().controlSize(.small)
                }
                Button {
                    Task { await guardEngine.refreshSymbiosis() }
                } label: {
                    Label("刷新扫描", systemImage: "arrow.clockwise")
                }
                .disabled(guardEngine.clashBusy)
            }

            if let note = guardEngine.clashActionNote {
                Label(note, systemImage: "checkmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(.teal)
            }
            if let err = guardEngine.clashError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

            discoveredClientsCard
            clashControllerCard
            clashLiveConnectionsCard
            overrideGeneratorCard
        }
    }

    // MARK: - 1. Discovered Local Proxy Clients

    private var discoveredClientsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("运行中的本机代理客户端", systemImage: "network.badge.shield.half.filled")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text("共发现 \(guardEngine.discoveredClients.count) 个可用端口")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if guardEngine.discoveredClients.isEmpty {
                Text("未检测到正在监听的已知代理客户端（支持 Clash Verge Rev / FlClash / Mihomo Party / ClashX / Surge / Stash / Hiddify / Sing-box 等）。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            } else {
                VStack(spacing: 0) {
                    ForEach(guardEngine.discoveredClients) { client in
                        if client.id != guardEngine.discoveredClients.first?.id {
                            Divider()
                        }
                        HStack(spacing: 12) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 8) {
                                    Text(client.clientName)
                                        .font(.callout.weight(.medium))
                                    Text(client.protocols.label)
                                        .font(.caption2.weight(.medium))
                                        .foregroundStyle(client.protocols.supportsHTTP ? .teal : .orange)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background((client.protocols.supportsHTTP ? Color.teal : Color.orange).opacity(0.12), in: Capsule())
                                }
                                Text("进程 \(client.processName) (PID \(String(client.pid)))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(verbatim: "127.0.0.1:\(String(client.port))")
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                            if client.protocols.supportsHTTP {
                                Button("设为上游") {
                                    guardEngine.adoptDiscoveredPort(client.port)
                                }
                                .controlSize(.small)
                                .disabled(guardEngine.isGuardProxyRunning)
                            } else {
                                Text("仅 SOCKS5")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 8)
                    }
                }
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - 2. Clash / Mihomo External Controller & Route Chain

    private var clashControllerCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Clash / Mihomo 控制器与 Claude 路由链路", systemImage: "cpu")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                if let snap = guardEngine.clashSnapshot {
                    Text("\(snap.endpoint.clientName) · \(snap.endpoint.transport.displayLabel)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }

            if let snap = guardEngine.clashSnapshot {
                HStack(spacing: 10) {
                    metaPill("内核", snap.kernelVersion, color: .teal)
                    metaPill("模式", snap.mode.uppercased(), color: snap.mode.lowercased() == "direct" ? .red : .teal)
                    metaPill("TUN", snap.tunEnabled ? "开启" : "关闭", color: snap.tunEnabled ? .teal : .secondary)
                    metaPill("IPv6", snap.ipv6Enabled ? "开启" : "关闭", color: .secondary)
                    if let mp = snap.mixedPort {
                        metaPill("混合端口", ":\(String(mp))", color: .secondary)
                    }
                    Spacer()
                }

                Divider()

                if let route = snap.claudeRoute {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 8) {
                            Image(systemName: routeStatusIcon(route))
                                .foregroundStyle(routeStatusColor(route))
                            Text("api.anthropic.com 命中链路")
                                .font(.callout.weight(.semibold))
                            Text(route.matchedRule)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(.quaternary.opacity(0.5), in: Capsule())
                        }

                        Text(route.chain.joined(separator: "  →  "))
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(routeStatusColor(route).opacity(0.07), in: RoundedRectangle(cornerRadius: 8))
                            .overlay { RoundedRectangle(cornerRadius: 8).strokeBorder(routeStatusColor(route).opacity(0.22)) }

                        if route.isDirect {
                            Label("高危：Claude 流量当前命中 DIRECT 直连！请在 Clash 切至规则/全局模式或导入下方防泄漏脚本。", systemImage: "xmark.octagon.fill")
                                .font(.callout)
                                .foregroundStyle(.red)
                        } else if route.hasDynamicGroupInChain {
                            Label("漂移风险：链路经过动态自动切组 \(route.dynamicGroups.joined(separator: "、"))，可能导致运行中静默换 IP/换地区。建议改为手动固定组（select）。", systemImage: "exclamationmark.triangle.fill")
                                .font(.callout)
                                .foregroundStyle(.orange)
                        } else if route.isRejected {
                            Label("当前规则将 Claude 设为 REJECT 阻断。", systemImage: "hand.raised.fill")
                                .font(.callout)
                                .foregroundStyle(.orange)
                        } else {
                            Label("当前路由指向手动固定节点「\(route.leafNode)」，未发现自动漂移组。", systemImage: "checkmark.circle.fill")
                                .font(.callout)
                                .foregroundStyle(.teal)
                        }

                        if let selector = route.selectorGroupForSwitching, !selector.candidates.isEmpty {
                            HStack(spacing: 10) {
                                Text("快捷切换组「\(selector.name)」")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Picker("目标节点", selection: Binding(
                                    get: {
                                        if guardEngine.selectedSwitchNode.isEmpty || !selector.candidates.contains(guardEngine.selectedSwitchNode) {
                                            return selector.current ?? selector.candidates.first ?? ""
                                        }
                                        return guardEngine.selectedSwitchNode
                                    },
                                    set: { guardEngine.selectedSwitchNode = $0 }
                                )) {
                                    ForEach(selector.candidates, id: \.self) { name in
                                        Text(name).tag(name)
                                    }
                                }
                                .labelsHidden()
                                .frame(maxWidth: 320)

                                Button("应用切换") {
                                    let target = guardEngine.selectedSwitchNode.isEmpty ? (selector.current ?? "") : guardEngine.selectedSwitchNode
                                    guard !target.isEmpty, target != selector.current else { return }
                                    Task { await guardEngine.switchClashNode(group: selector.name, node: target) }
                                }
                                .disabled(guardEngine.clashBusy || guardEngine.selectedSwitchNode.isEmpty || guardEngine.selectedSwitchNode == selector.current)
                                Spacer()
                            }
                            .padding(.top, 2)
                        }
                    }
                } else {
                    Text("控制器已连接，但暂未解析到明确匹配 api.anthropic.com 的规则。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("未连接到运行中的 Clash / Mihomo External Controller（支持自动读取 Clash Verge Rev 的 Unix Socket、Mihomo Party、FlClash、ClashX、Stash 配置）。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - 3. Live Clash /connections Monitoring

    private var clashLiveConnectionsCard: some View {
        let snap = guardEngine.clashSnapshot
        let conns = snap?.claudeConnections ?? []
        let violations = snap?.directViolations ?? []

        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("Clash 实时 Claude 活跃连接（/connections）", systemImage: "waveform.path")
                    .font(.subheadline.weight(.semibold))
                if !violations.isEmpty {
                    Text("发现 \(violations.count) 条直连违规")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.red)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(.red.opacity(0.12), in: Capsule())
                }
                Spacer()
                if let snap {
                    Text("活跃 Claude \(conns.count) / 全局 \(snap.totalConnections)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if !violations.isEmpty {
                    Button("一键切断违规直连") {
                        Task { await guardEngine.closeAllDirectViolations() }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .controlSize(.small)
                    .disabled(guardEngine.clashBusy)
                }
            }

            if snap == nil {
                Text("连接 Clash 控制器后，将在此实时显示经过 Clash 内核的所有 Claude/Anthropic 连接并抓出违规直连。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if conns.isEmpty {
                Text("当前 Clash 内核中没有活跃的 Claude / Anthropic 连接（运行 Claude Code 或打开 claude.ai 后点「刷新扫描」即可查看）。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            } else {
                VStack(spacing: 0) {
                    ForEach(conns) { conn in
                        if conn.id != conns.first?.id { Divider() }
                        HStack(spacing: 10) {
                            Image(systemName: conn.isViolation ? "xmark.octagon.fill" : (conn.isRejected ? "hand.raised.fill" : "checkmark.circle.fill"))
                                .foregroundStyle(conn.isViolation ? .red : (conn.isRejected ? .orange : .teal))
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: "\(conn.host):\(String(conn.port)) (\(conn.network.uppercased()))")
                                    .font(.system(.callout, design: .monospaced))
                                    .textSelection(.enabled)
                                Text("规则：\(conn.rule)\(conn.rulePayload.isEmpty ? "" : "(\(conn.rulePayload))") · 链路：\(conn.chains.reversed().joined(separator: " → "))")
                                    .font(.caption)
                                    .foregroundStyle(conn.isViolation ? .red : .secondary)
                            }
                            Spacer()
                            Text("↑\(formatBytes(conn.upload)) ↓\(formatBytes(conn.download))")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                            Button("断开") {
                                Task { await guardEngine.closeClashConnection(id: conn.id) }
                            }
                            .controlSize(.small)
                            .disabled(guardEngine.clashBusy)
                        }
                        .padding(.vertical, 7)
                    }
                }
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
    }

    // MARK: - 4. 1-Click Lazy Clash Verge Installer + Override Generator

    private var overrideGeneratorCard: some View {
        let preferredNode = guardEngine.clashSnapshot?.claudeRoute?.leafNode
        let codeText: String = {
            switch guardEngine.overrideFormat {
            case .vergeJS:
                return ClashOverrideGenerator.generateVergeJavaScript(preferredNodeName: preferredNode)
            case .clashYAML:
                return ClashOverrideGenerator.generateYAMLSnippet()
            }
        }()

        return VStack(alignment: .leading, spacing: 11) {
            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Label("懒人一键写入 Clash Verge 防泄漏扩展脚本", systemImage: "wand.and.stars")
                            .font(.subheadline.weight(.semibold))
                        scriptStatusBadge
                    }
                    Text("自动写入 Clash Verge 全局扩展脚本（profiles/Script.js）并原子备份原脚本：自动置顶你当前合规节点、创建 Claude-Pin 手动组、屏蔽 QUIC/STUN，并把海外与 Claude DNS 锁至代理远端 DoH 根治 DNS/ECS 泄漏")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
            }

            // Lazy 1-click Clash Verge action bar
            HStack(spacing: 10) {
                switch guardEngine.clashScriptStatus {
                case .vergeNotInstalled:
                    Text("未检测到 Clash Verge Rev 配置目录，可使用下方按钮手动复制规则")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                case .notInstalled(let hasCustom):
                    Button {
                        guardEngine.installVergeScript()
                    } label: {
                        Label("一键写入 Clash Verge", systemImage: "bolt.fill")
                    }
                    .buttonStyle(.borderedProminent)

                    if hasCustom {
                        Text("检测到已有自定义脚本，写入时会自动备份并串联保留原逻辑")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }

                case let .installed(chained, activeInKernel):
                    Button {
                        guardEngine.installVergeScript()
                    } label: {
                        Label("更新已写入脚本", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .buttonStyle(.borderedProminent)

                    Button {
                        guardEngine.openClashVergeForReload()
                    } label: {
                        Label(activeInKernel ? "打开 Clash Verge" : "打开 Clash Verge 重载生效", systemImage: "arrow.up.forward.app")
                    }

                    Button("一键还原原始脚本") {
                        guardEngine.confirmRestoreVergeScript = true
                    }

                    if chained {
                        Text("已串联保留原有自定义脚本")
                            .font(.caption)
                            .foregroundStyle(.teal)
                    }
                }

                Spacer()

                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(codeText, forType: .string)
                    guardEngine.copiedOverride = true
                    Task {
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                        guardEngine.copiedOverride = false
                    }
                } label: {
                    Label(guardEngine.copiedOverride ? "已复制" : "仅复制代码", systemImage: guardEngine.copiedOverride ? "checkmark" : "doc.on.doc")
                }
            }

            if case .installed(_, let activeInKernel) = guardEngine.clashScriptStatus, !activeInKernel {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle.fill").foregroundStyle(.orange)
                    Text("脚本已写入 profiles/Script.js，但 Clash Verge 内核尚未加载 Claude-Pin：点「打开 Clash Verge 重载生效」后在订阅页点一下当前订阅右侧的刷新/重新启用图标，再回到本页点「刷新扫描」即可看到变绿生效。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(9)
                .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            }

            Picker("覆写格式", selection: $guardEngine.overrideFormat) {
                ForEach(OverrideFormat.allCases) { f in
                    Text(f.rawValue).tag(f)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 440)

            ScrollView([.vertical, .horizontal]) {
                Text(codeText)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 200)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay { RoundedRectangle(cornerRadius: 8).strokeBorder(.quaternary) }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
        .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(.quaternary) }
        .confirmationDialog("还原原始 Clash Verge Script.js？", isPresented: $guardEngine.confirmRestoreVergeScript, titleVisibility: .visible) {
            Button("还原原始脚本", role: .destructive) {
                guardEngine.restoreVergeScript()
            }
        }
    }

    @ViewBuilder
    private var scriptStatusBadge: some View {
        switch guardEngine.clashScriptStatus {
        case .vergeNotInstalled:
            EmptyView()
        case .notInstalled:
            Text("未写入")
                .font(.caption2.weight(.medium))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(.quaternary.opacity(0.6), in: Capsule())
        case .installed(_, true):
            Text("已在内核中生效")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.teal)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(.teal.opacity(0.14), in: Capsule())
        case .installed(_, false):
            Text("已写入 · 待 Clash 重载")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.orange)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(.orange.opacity(0.14), in: Capsule())
        }
    }

    // MARK: - Helpers

    private func metaPill(_ label: String, _ value: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Text(label).foregroundStyle(.secondary)
            Text(value).fontWeight(.medium).foregroundStyle(color)
        }
        .font(.caption)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(color.opacity(0.1), in: Capsule())
    }

    private func routeStatusIcon(_ route: ClashRouteResolution) -> String {
        if route.isDirect { return "xmark.octagon.fill" }
        if route.hasDynamicGroupInChain || route.isRejected { return "exclamationmark.triangle.fill" }
        return "checkmark.circle.fill"
    }

    private func routeStatusColor(_ route: ClashRouteResolution) -> Color {
        if route.isDirect { return .red }
        if route.hasDynamicGroupInChain || route.isRejected { return .orange }
        return .teal
    }

    private func formatBytes(_ count: Int64) -> String {
        if count < 1024 { return "\(count)B" }
        if count < 1024 * 1024 { return String(format: "%.1fK", Double(count) / 1024.0) }
        return String(format: "%.1fM", Double(count) / (1024.0 * 1024.0))
    }
}
