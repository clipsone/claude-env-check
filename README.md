# Claude 环境体检 (v1.2.0 · macOS + Windows 双平台)

原生轻量级、零 Root / 零管理员权限的 **Claude 本地熔断守卫 + Clash/Mihomo 深度共生 + 多源 IP 黑名单投票 + 全家桶隔离工作台**：

- **macOS 原生版（Apple Silicon macOS 13+）**：纯 Swift 6 / SwiftUI 原生应用（< 5 MB，零 Node.js，零 Root 守护进程，配备原生 Retina 应用图标）。
- **Windows 原生版（Windows 10/11 amd64）**：纯 Go 零 CGO 静态单文件 `.exe`（零 DLL / 零 .NET / 零 Node 依赖，原生 Win32 系统托盘 + 本地加密令牌 Web 控制台，免 UAC 管理员权限）。

## 核心能力（v1.2.0 全平台闭环）

1. **20 项零误报科学体检与多源黑名单投票**：
   - Anthropic 官方 **185 国**支持清单校验（新加坡/台湾/英/德/法/加/日/美等全部零误报）；
   - 三源 GeoIP 交叉核验（`ipwho.is` + `ipinfo.io`/`api.ip.sb` + `Cloudflare Trace`）+ 统一 ASN 住宅/云机房推断；
   - **内置多源 IP 黑名单与纯净度投票**：并行实测 `Spamhaus ZEN / DROP`、`Tor 出口库`、`DroneBL`、`UCEPROTECT L1` 与 ASN 特征，精准过滤公共 DNS 限流码（`127.255.255.*`）与住宅动态段（PBL `127.0.0.10/.11`），坚持**多源共识、拒绝单源误报**；
   - IPv4/IPv6 双栈防泄漏 + 真实 DNS 递归出口与 ECS 网段泄漏实测 + Fake-IP TUN 探测 + 进程级 `TZ` 对齐识别 + 48h 漂移分级预警与一键重置。
2. **本地无 Root/无管理员熔断转发网关（支持 HTTP CONNECT & 纯 SOCKS5 上游）**：
   - 仅监听 `127.0.0.1:17899`，透明转发（零 MITM、拒绝回环 SSRF `403`），**自动识别 HTTP CONNECT 与 RFC 1928 纯 SOCKS5 上游**（可把纯 SOCKS5 代理自动桥接给只认 HTTP 代理的 Claude Code）；
   - 30 秒后台巡检 + **2 秒本地 Clash 节点切换秒级预熔断** + macOS 网卡变化与休眠唤醒 Fail-Closed，出口漂移或代理掉线时**毫秒级切断所有活跃隧道并返回 HTTP 503**，绝不影响其他应用或公司 VPN。
3. **多代理客户端自动发现 & 一键防泄漏脚本**：
   - 独立双协议探测 HTTP + SOCKS5，兼容 Clash Verge Rev / 旧版 Clash Verge / Mihomo Party / FlClash / Surge / Stash / v2rayN / Hiddify / Sing-box；
   - 直连 Clash/Mihomo External Controller（macOS 原生支持 Unix Socket + TCP，Windows 支持 TCP）监控 `/connections` 并一键切断违规直连；
   - **多客户端懒人一键写入防泄漏脚本**：支持 **Clash Verge Rev、旧版 Clash Verge、Mihomo Party、FlClash**，自动原子备份原脚本、IIFE 串联保留用户自定义逻辑、支持一键无损还原。
4. **开机静默常驻与自动护卫**：
   - macOS 使用原生 `SMAppService.mainApp` 登录项（免 Root），Windows 使用当前用户 `HKCU\...\Run`（免管理员），重启后静默驻留菜单栏/托盘并自动等待代理就绪拉起守卫。
5. **终端防漏安全壳（`claude-safe`）**：
   - 一键安装 `~/.local/bin/claude-safe`（macOS）或 `%USERPROFILE%\.local\bin\claude-safe.cmd`（Windows）；
   - 每次启动 Claude Code 前 < 50ms 探测本地 `127.0.0.1:<port>/__claude_guard_health`（零外网流量），守卫离线或熔断时直接拦截并提示原因，彻底杜绝忘开守卫裸连。
6. **Claude 全家桶安全工作台**：
   - **隔离浏览器启动器**：以独立 `--user-data-dir` 启动本机 Chrome / Edge / Brave / Vivaldi，自动启用 `--disable-quic`、防 WebRTC 直连 UDP、`Accept-Language` 自动写入 `Default/Preferences` 与进程级 `TZ`（零 Chrome 不受支持标记横幅、绝不复制日常书签）；
   - **Claude Desktop 对齐启动与安全清理**：同时锁定 Chromium 渲染层（`--proxy-server` + `--disable-quic`）与 Electron Node 主进程代理，macOS 版支持按项勾选并仅移入系统废纸篓（绝不触碰 `~/.claude`）；
   - **48h 连接审计（CSV/JSON 导出）+ 48h 出口漂移历史 + 被动式 GitHub Releases 更新检查**。

## 下载安装

前往 [GitHub Releases](https://github.com/clipsone/claude-env-check/releases) 下载对应平台安装包：

- **macOS (Apple Silicon, macOS 13+)**：下载 `Claude-Environment-Check-*-arm64.dmg`，拖入「应用程序」。
  - 首次打开若遇本地签名提示，在「访达 → 应用程序」中右键选择「打开」，或运行 `xattr -dr com.apple.quarantine "/Applications/Claude 环境体检.app"`。
- **Windows (Windows 10/11 64 位)**：下载 `Claude-Environment-Check-*-windows-amd64.exe`，双击直接运行（无需安装，无需管理员权限，自动打开本地控制台并在右下角系统托盘常驻）。

## 本地测试与构建

### macOS
```bash
# 运行完整 Swift 6 自动化测试套件（零网络依赖、不污染本机配置）
bash test.sh

# 测试 + Swift 6 严格编译 + 覆盖安装到 /Applications + 打包 arm64 DMG
bash build.sh --test --install --dmg
```

### Windows (Go 1.22+，零第三方依赖)
```bash
cd windows
go test -v ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o ../build/Claude-Environment-Check-1.2.0-windows-amd64.exe ./cmd/claude-env-check
```
