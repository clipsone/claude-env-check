# Claude 环境体检 (v1.1.2)

纯原生 Swift 6 / SwiftUI 实现的 Apple Silicon macOS **无 Root 本地熔断守卫 + Clash/Mihomo 深度共生 + Claude 全家桶工作台**（< 5 MB、零 Node.js、零 Root 守护进程、零全局时区篡改、与 Clash Verge / FlClash / Surge / 公司 VPN 100% 和平共生）。

## 六大核心能力

1. **19 项零误报科学体检与综合合规判定**：
   - Anthropic 官方 **185 国**支持清单校验（新加坡/台湾/英/德/法/加/日/美等全部零误报）；
   - 三源 GeoIP 交叉核验（`ipwho.is` + `ipinfo.io`/`api.ip.sb` + `Cloudflare Trace`）+ 统一 ASN 住宅/云机房推断；
   - IPv4/IPv6 双栈防泄漏 + 原生 `mDNSResponder` 真实 DNS 递归出口与 ECS 网段泄漏实测 + Fake-IP TUN 探测；
   - Claude Code 全链路配置审计（死代理端口、`NO_PROXY` 误放行、`settings.local.json` 与 `~/.zshrc` 冲突，绝不读 API Key）+ 识别进程级 `TZ` 对齐 + 一键复制脱敏 Markdown 报告。
2. **纯 Swift 无 Root 本地熔断转发网关 & 菜单栏红绿灯常驻**：
   - `Network.framework` 本地 `127.0.0.1:17899` 透明 HTTP `CONNECT` 转发器（零 MITM、拒绝回环 SSRF）；
   - 后台 30s 巡检 + `NWPathMonitor` 网卡切换 + `NSWorkspace.didWakeNotification` 休眠唤醒 Fail-Closed；
   - 出口漂移至不支持地区、多源分流冲突、上游掉线或触发「严格锁出口 IP」时，**毫秒级切断所有活跃隧道并拒绝新连接（HTTP 503）**，仅阻断 Claude，绝不影响其他软件或公司 VPN；
   - 原生 `MenuBarExtra` 菜单栏常驻、关窗后台守护、退出同步恢复配置、异常强杀后支持一键无缝接管。
3. **多代理客户端自动发现 & Clash/Mihomo 深度共生**：
   - 独立双协议探测 HTTP CONNECT + SOCKS5，兼容 root Service Mode 内核（Clash Verge Rev / FlClash / Mihomo Party / ClashX / Surge / Stash / Hiddify / Sing-box）；
   - 纯 Swift 直连 Clash/Mihomo External Controller（原生支持 **Unix Domain Socket + TCP**，密钥仅留内存），解析 `api.anthropic.com` 实际路由链路、预警 `URLTest`/`Fallback` 漂移组、实时监控 `/connections` 并一键切断违规直连；
   - **懒人一键写入 Clash Verge 全局扩展脚本（`profiles/Script.js`）**：无需手动复制粘贴，一键原子备份并写入（已有自定义脚本自动串联保留、支持一键无损还原），自动置顶当前合规节点、创建 `Claude-Pin` 手动组、屏蔽 QUIC/STUN、代理远端 DoH 根治 DNS/ECS 泄漏；
   - **2 秒本地节点变动秒级预熔断**：守卫运行中每 2 秒零外网流量轮询本地 Clash Unix Socket，一旦手动切节点立即先行熔断再复检出口，彻底堵死 30 秒切换空窗。
4. **进程级 `TZ` / `LANG` 对齐注入（零全局系统污染）**：
   - 按实测出口地区为 Claude Code、隔离浏览器和 Claude Desktop 单独注入进程级 `TZ`/`LANG`/`LC_ALL`，关闭防护时原子无损恢复，绝不改动 macOS 全局系统时区。
5. **macOS Claude 全家桶安全工作台**：
   - **隔离浏览器启动器**：以独立 `--user-data-dir` 启动本机 Chrome/Brave/Edge/Vivaldi，自动启用 `--disable-quic`、`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`、HTTP `CONNECT` 代理远端解析、进程级 `TZ` 与 `Accept-Language` 对齐（零 Chrome 提示横幅、绝不偷偷复制日常书签或 Cookie）；
   - **Claude Desktop 专属对齐启动与安全清理**：支持同时锁定 Chromium 渲染层（`--proxy-server` + `--disable-quic`）与 Node 主进程代理，按项勾选缓存/Cookie/数据目录，严格防符号链接校验后**仅移入系统废纸篓**（绝不 `rm -rf`，绝不触碰 `~/.claude`）；
   - **被动式 GitHub Releases 更新检查**：纯只读校验 SemVer，绝不自动下载或执行安装包。
6. **48 小时连接审计日志 + 48 小时出口漂移追踪 + 多历史命名快照基线对比**：
   - 支持最多 10 份命名快照自由对比、连接审计 CSV/JSON 导出、历史漂移分级预警与一键重置。

## 下载安装

直接前往 [Releases 页面](https://github.com/clipsone/claude-env-check/releases) 下载最新的 `Claude-Environment-Check-*-arm64.dmg`（适用于 Apple Silicon macOS 13+），拖入「应用程序」即可。

> 注：未公证的本地签名应用首次打开时，如遇 macOS 提示，可在「访达 → 应用程序」中右键「Claude 环境体检」选择「打开」，或执行 `xattr -dr com.apple.quarantine "/Applications/Claude 环境体检.app"`。

## 本地测试、构建与打包

```bash
# 运行完整自动化测试套件（不污染本机配置，零网络依赖；加 --live 可追加实机冒烟）
bash test.sh

# 一键：运行测试 + Swift 6 严格编译 + 覆盖安装到 /Applications + 打包 arm64 DMG
bash build.sh --test --install --dmg

# 可选：使用 Apple Developer ID 签名与 Hardened Runtime
bash build.sh --test --dmg --sign "Developer ID Application: Your Name (TEAMID)"
```
