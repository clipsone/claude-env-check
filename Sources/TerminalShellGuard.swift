import Foundation

enum TerminalGuardStatus: Equatable, Sendable {
    case notInstalled
    case installed(path: String, pathInUserShell: Bool)
    case foreignFileExists(path: String)
}

enum TerminalShellGuard {
    static let managedMarker = "# CLAUDE-ENV-CHECK-MANAGED-WRAPPER-V1"

    static func defaultScriptURL(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent(".local/bin/claude-safe")
    }

    static func inspectStatus(
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        pathEnv: String = ProcessInfo.processInfo.environment["PATH"] ?? ""
    ) -> TerminalGuardStatus {
        let url = defaultScriptURL(home: home)
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path) else {
            return .notInstalled
        }
        guard let content = try? String(contentsOf: url, encoding: .utf8),
              content.contains(managedMarker) else {
            return .foreignFileExists(path: url.path)
        }
        let binDir = url.deletingLastPathComponent().path
        let inPath = pathEnv.split(separator: ":").contains { String($0) == binDir }
        return .installed(path: url.path, pathInUserShell: inPath)
    }

    static func generateWrapperScript() -> String {
        """
        #!/bin/bash
        \(managedMarker)
        # Claude Code terminal anti-leak wrapper installed by Claude 环境体检 (v1.2.0)
        # Verifies local circuit-breaker guard health (<50ms, zero external traffic) before executing `claude`.
        set -euo pipefail

        BYPASS=0
        ARGS=()
        for arg in "$@"; do
            if [ "$arg" = "--bypass-guard" ]; then
                BYPASS=1
            else
                ARGS+=("$arg")
            fi
        done

        find_real_claude() {
            local self_path
            self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
            IFS=':' read -ra dirs <<< "${PATH:-/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin}"
            for dir in "${dirs[@]}"; do
                [ -z "$dir" ] && continue
                local cand="$dir/claude"
                if [ -x "$cand" ] && [ ! -d "$cand" ]; then
                    local real_cand
                    real_cand="$(cd "$(dirname "$cand")" && pwd)/$(basename "$cand")"
                    if [ "$real_cand" != "$self_path" ]; then
                        printf '%s\\n' "$cand"
                        return 0
                    fi
                fi
            done
            return 1
        }

        REAL_CLAUDE="$(find_real_claude || true)"
        if [ -z "$REAL_CLAUDE" ]; then
            printf '\\033[31m[claude-safe] 未在 PATH 中找到 claude 可执行文件。\\033[0m\\n' >&2
            exit 127
        fi

        if [ "$BYPASS" -eq 1 ]; then
            printf '\\033[33m[claude-safe] 已按 --bypass-guard 跳过本地守卫校验，直接启动 claude。\\033[0m\\n' >&2
            exec "$REAL_CLAUDE" "${ARGS[@]}"
        fi

        SETTINGS_FILE="$HOME/.claude/settings.json"
        if [ ! -f "$SETTINGS_FILE" ]; then
            printf '\\033[31m[claude-safe] 已拦截：未找到 ~/.claude/settings.json，请先在「Claude 环境体检」启动熔断守卫。\\033[0m\\n' >&2
            printf '提示：如确需临时绕过，请使用 claude-safe --bypass-guard\\n' >&2
            exit 77
        fi

        PROXY_PORT="$(/usr/bin/sed -nE 's/.*"(HTTPS_PROXY|HTTP_PROXY|https_proxy|http_proxy)"[[:space:]]*:[[:space:]]*"http:\\/\\/127\\.0\\.0\\.1:([0-9]{2,5})".*/\\2/p' "$SETTINGS_FILE" | head -n 1)"
        if [ -z "$PROXY_PORT" ]; then
            printf '\\033[31m[claude-safe] 已拦截：~/.claude/settings.json 未配置本地 127.0.0.1 守护代理端口，防止直连暴露！\\033[0m\\n' >&2
            printf '请先打开「Claude 环境体检」启动熔断守卫（或临时传 --bypass-guard）。\\n' >&2
            exit 77
        fi

        HEALTH_OUT="$(/usr/bin/curl -sS --noproxy '*' --connect-timeout 1 --max-time 2 -w '\\n%{http_code}' "http://127.0.0.1:${PROXY_PORT}/__claude_guard_health" 2>/dev/null || true)"
        HTTP_CODE="$(printf '%s' "$HEALTH_OUT" | tail -n 1)"
        BODY="$(printf '%s' "$HEALTH_OUT" | sed '$d')"

        if [ "$HTTP_CODE" = "200" ] && printf '%s' "$BODY" | /usr/bin/grep -q '"state":"open"'; then
            exec "$REAL_CLAUDE" "${ARGS[@]}"
        elif [ "$HTTP_CODE" = "503" ]; then
            printf '\\033[31m[claude-safe] 已拦截：本地熔断守卫 (127.0.0.1:%s) 当前处于熔断阻断状态！\\033[0m\\n' "$PROXY_PORT" >&2
            printf '详情：%s\\n' "$BODY" >&2
            printf '请先在「Claude 环境体检」确认节点合规并解除熔断。\\n' >&2
            exit 78
        else
            printf '\\033[31m[claude-safe] 已拦截：本地熔断守卫 (127.0.0.1:%s) 未运行或非熔断网关端口！\\033[0m\\n' "$PROXY_PORT" >&2
            printf '请先打开「Claude 环境体检」开启熔断守卫（或临时使用 claude-safe --bypass-guard）。\\n' >&2
            exit 77
        fi
        """
    }

    static func install(home: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> URL {
        let fm = FileManager.default
        let targetURL = defaultScriptURL(home: home)
        let binDir = targetURL.deletingLastPathComponent()
        try fm.createDirectory(at: binDir, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o755])
        try PathSafety.verifyNoSymlinks(at: binDir, within: home)
        if fm.fileExists(atPath: targetURL.path) {
            try PathSafety.verifyNoSymlinks(at: targetURL, within: home)
            if let existing = try? String(contentsOf: targetURL, encoding: .utf8),
               !existing.contains(managedMarker) {
                throw NSError(
                    domain: "local.claude-environment-check.shellguard",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "\(targetURL.path) 已存在非本工具创建的脚本，为安全起见未覆盖。"]
                )
            }
        }
        let script = generateWrapperScript()
        try Data(script.utf8).write(to: targetURL, options: .atomic)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: targetURL.path)
        return targetURL
    }

    static func uninstall(home: URL = FileManager.default.homeDirectoryForCurrentUser) throws {
        let fm = FileManager.default
        let targetURL = defaultScriptURL(home: home)
        guard fm.fileExists(atPath: targetURL.path) else { return }
        try PathSafety.verifyNoSymlinks(at: targetURL, within: home)
        guard let existing = try? String(contentsOf: targetURL, encoding: .utf8),
              existing.contains(managedMarker) else {
            throw NSError(
                domain: "local.claude-environment-check.shellguard",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "\(targetURL.path) 不是本工具安装的安全壳，已拒绝删除。"]
            )
        }
        try fm.removeItem(at: targetURL)
    }

    static func shellAliasSnippet() -> String {
        """
        export PATH="$HOME/.local/bin:$PATH"
        alias claude='claude-safe'
        """
    }
}
