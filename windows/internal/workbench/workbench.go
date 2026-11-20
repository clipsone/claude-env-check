package workbench

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/clipsone/claude-env-check/windows/internal/regions"
)

const WrapperMarker = "REM CLAUDE-ENV-CHECK-MANAGED-WRAPPER-V1"

type BrowserInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ExecutablePath string `json:"executablePath"`
}

type LaunchSpec struct {
	ExecutablePath string            `json:"executablePath"`
	Arguments      []string          `json:"arguments"`
	Environment    map[string]string `json:"environment"`
	ProfileDir     string            `json:"profileDir"`
	Language       string            `json:"language"`
}

func DiscoverWindowsBrowsers() []BrowserInfo {
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	localApp := os.Getenv("LOCALAPPDATA")

	candidates := []struct {
		id    string
		name  string
		paths []string
	}{
		{"chrome", "Google Chrome", []string{
			filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(localApp, "Google", "Chrome", "Application", "chrome.exe"),
		}},
		{"edge", "Microsoft Edge", []string{
			filepath.Join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
		}},
		{"brave", "Brave Browser", []string{
			filepath.Join(pf, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			filepath.Join(localApp, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
		}},
		{"vivaldi", "Vivaldi", []string{
			filepath.Join(localApp, "Vivaldi", "Application", "vivaldi.exe"),
			filepath.Join(pf, "Vivaldi", "Application", "vivaldi.exe"),
		}},
	}

	var found []BrowserInfo
	for _, c := range candidates {
		for _, p := range c.paths {
			if p == "" {
				continue
			}
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				found = append(found, BrowserInfo{ID: c.id, Name: c.name, ExecutablePath: p})
				break
			}
		}
	}
	return found
}

func BuildBrowserLaunchSpec(browser BrowserInfo, stateDir string, proxyPort int, countryCode, geoTZ, startURL string) LaunchSpec {
	profileDir := filepath.Join(stateDir, "isolated-browser-profiles", browser.ID)
	args := []string{
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-quic",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
	}
	env := map[string]string{}
	var bcp47 string
	if countryCode != "" {
		loc := regions.RecommendedProcessLocale(countryCode, geoTZ)
		bcp47 = loc.BCP47
		args = append(args, "--lang="+bcp47)
		env["TZ"] = loc.TimeZone
		env["LANG"] = loc.Lang
		env["LC_ALL"] = loc.Lang
		env["LANGUAGE"] = strings.ReplaceAll(regions.AcceptLanguages(bcp47), ",", ":")
	}
	if proxyPort >= 1 && proxyPort <= 65535 {
		proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
		// HTTP CONNECT resolves hostnames remotely on the proxy; omitting --host-resolver-rules avoids Chrome's unsupported-flag infobar.
		args = append(args, "--proxy-server="+proxyURL)
		env["HTTP_PROXY"] = proxyURL
		env["HTTPS_PROXY"] = proxyURL
	}
	u := strings.TrimSpace(startURL)
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		u = "https://claude.ai"
	}
	args = append(args, u)
	return LaunchSpec{
		ExecutablePath: browser.ExecutablePath,
		Arguments:      args,
		Environment:    env,
		ProfileDir:     profileDir,
		Language:       bcp47,
	}
}

func ApplyProfileLanguagePreferences(profileDir, bcp47 string) error {
	if bcp47 == "" {
		return nil
	}
	defDir := filepath.Join(profileDir, "Default")
	if err := os.MkdirAll(defDir, 0o700); err != nil {
		return err
	}
	prefsPath := filepath.Join(defDir, "Preferences")
	root := map[string]any{}
	if raw, err := os.ReadFile(prefsPath); err == nil {
		_ = json.Unmarshal(raw, &root)
	}
	intl, _ := root["intl"].(map[string]any)
	if intl == nil {
		intl = map[string]any{}
	}
	accept := regions.AcceptLanguages(bcp47)
	intl["accept_languages"] = accept
	intl["selected_languages"] = accept
	root["intl"] = intl
	out, err := json.Marshal(root)
	if err != nil {
		return err
	}
	return os.WriteFile(prefsPath, out, 0o600)
}

func LaunchBrowser(spec LaunchSpec) error {
	if err := os.MkdirAll(spec.ProfileDir, 0o700); err != nil {
		return err
	}
	_ = ApplyProfileLanguagePreferences(spec.ProfileDir, spec.Language)
	cmd := exec.Command(spec.ExecutablePath, spec.Arguments...)
	cmd.Env = mergeEnv(spec.Environment)
	return cmd.Start()
}

func DiscoverClaudeDesktopExe() string {
	localApp := os.Getenv("LOCALAPPDATA")
	candidates := []string{
		filepath.Join(localApp, "AnthropicClaude", "claude.exe"),
		filepath.Join(localApp, "Programs", "claude-desktop", "Claude.exe"),
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func LaunchClaudeDesktopAligned(exePath, stateDir string, proxyPort int, countryCode, geoTZ string, isolated bool) error {
	if exePath == "" {
		return errors.New("未找到 Windows 版 Claude Desktop (claude.exe)")
	}
	args := []string{
		"--disable-quic",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
	}
	env := map[string]string{}
	var bcp47 string
	if isolated {
		dir := filepath.Join(stateDir, "isolated-claude-desktop")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		args = append(args, "--user-data-dir="+dir)
	}
	if countryCode != "" {
		loc := regions.RecommendedProcessLocale(countryCode, geoTZ)
		bcp47 = loc.BCP47
		args = append(args, "--lang="+bcp47)
		env["TZ"] = loc.TimeZone
		env["LANG"] = loc.Lang
		env["LC_ALL"] = loc.Lang
		env["LANGUAGE"] = strings.ReplaceAll(regions.AcceptLanguages(bcp47), ",", ":")
	}
	if proxyPort >= 1 && proxyPort <= 65535 {
		proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
		args = append(args, "--proxy-server="+proxyURL)
		env["HTTP_PROXY"] = proxyURL
		env["HTTPS_PROXY"] = proxyURL
		env["ALL_PROXY"] = proxyURL
		env["NODE_USE_ENV_PROXY"] = "1"
	}
	if isolated && bcp47 != "" {
		_ = ApplyProfileLanguagePreferences(filepath.Join(stateDir, "isolated-claude-desktop"), bcp47)
	}
	cmd := exec.Command(exePath, args...)
	cmd.Env = mergeEnv(env)
	return cmd.Start()
}

// Terminal Anti-Leak Shell Guard for Windows (claude-safe.cmd & claude-safe.ps1)
func WrapperDir(home string) string {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".local", "bin")
}

func IsShellGuardInstalled(home string) bool {
	p := filepath.Join(WrapperDir(home), "claude-safe.cmd")
	raw, err := os.ReadFile(p)
	return err == nil && strings.Contains(string(raw), WrapperMarker)
}

func GenerateWindowsCmdWrapper() string {
	return `@echo off
` + WrapperMarker + `
setlocal EnableDelayedExpansion
if "%~1"=="--bypass-guard" (
  shift
  echo [claude-safe] Bypassing local guard by explicit request... >&2
  claude %*
  exit /b %ERRORLEVEL%
)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s = Join-Path $env:USERPROFILE '.claude\settings.json'; " ^
  "if (-not (Test-Path $s)) { Write-Host '[claude-safe] Blocked: missing ~/.claude/settings.json' -ForegroundColor Red; exit 77 }; " ^
  "$cfg = Get-Content $s -Raw | ConvertFrom-Json; " ^
  "$p = if ($cfg.env.HTTPS_PROXY) { $cfg.env.HTTPS_PROXY } else { $cfg.env.HTTP_PROXY }; " ^
  "if ($p -notmatch '^http://127\.0\.0\.1:(\d+)$') { Write-Host '[claude-safe] Blocked: local 127.0.0.1 guard proxy not configured.' -ForegroundColor Red; exit 77 }; " ^
  "$port = $Matches[1]; " ^
  "try { $r = Invoke-WebRequest -UseBasicParsing -NoProxy -TimeoutSec 2 -Uri ('http://127.0.0.1:' + $port + '/__claude_guard_health'); " ^
  "  if ($r.StatusCode -eq 200 -and $r.Content -match '\"state\":\"open\"') { exit 0 } else { exit 78 } " ^
  "} catch { Write-Host ('[claude-safe] Blocked: local guard on 127.0.0.1:' + $port + ' is offline or tripped.') -ForegroundColor Red; exit 77 }"
if errorlevel 1 exit /b %ERRORLEVEL%
claude %*
`
}

func InstallShellGuard(home string) (string, error) {
	dir := WrapperDir(home)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	cmdPath := filepath.Join(dir, "claude-safe.cmd")
	if err := os.WriteFile(cmdPath, []byte(GenerateWindowsCmdWrapper()), 0o755); err != nil {
		return "", err
	}
	return cmdPath, nil
}

func UninstallShellGuard(home string) error {
	cmdPath := filepath.Join(WrapperDir(home), "claude-safe.cmd")
	raw, err := os.ReadFile(cmdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !strings.Contains(string(raw), WrapperMarker) {
		return errors.New("claude-safe.cmd 不是本工具安装的文件，已拒绝删除")
	}
	return os.Remove(cmdPath)
}

func mergeEnv(extra map[string]string) []string {
	out := os.Environ()
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}
