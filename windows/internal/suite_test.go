package internal_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clipsone/claude-env-check/windows/internal/clash"
	"github.com/clipsone/claude-env-check/windows/internal/diagnostics"
	"github.com/clipsone/claude-env-check/windows/internal/proxy"
	"github.com/clipsone/claude-env-check/windows/internal/regions"
	"github.com/clipsone/claude-env-check/windows/internal/reputation"
	"github.com/clipsone/claude-env-check/windows/internal/workbench"
)

func TestRegions185Parity(t *testing.T) {
	if len(regions.SupportedCodes) != 185 {
		t.Fatalf("expected 185 Anthropic supported countries, got %d", len(regions.SupportedCodes))
	}
	for _, ok := range []string{"US", "JP", "SG", "TW", "GB", "DE", "FR", "CA", "AU"} {
		if regions.Support(ok) != regions.Supported {
			t.Fatalf("%s must be supported", ok)
		}
	}
	for _, bad := range []string{"CN", "HK", "MO", "RU", "IR", "KP", "BY"} {
		if regions.Support(bad) != regions.Unsupported {
			t.Fatalf("%s must be unsupported", bad)
		}
	}
	loc := regions.RecommendedProcessLocale("US", "America/New_York")
	if loc.TimeZone != "America/New_York" || loc.BCP47 != "en-US" {
		t.Fatalf("unexpected US locale: %+v", loc)
	}
}

func TestIPReputationMultiSourceVoting(t *testing.T) {
	rev, ok := reputation.ReverseIPv4("48.45.153.58")
	if !ok || rev != "58.153.45.48" {
		t.Fatalf("ReverseIPv4 failed: %q %v", rev, ok)
	}
	if _, ok := reputation.ReverseIPv4("2606:4700::1"); ok {
		t.Fatal("IPv6 must be rejected by ReverseIPv4")
	}

	// Spamhaus public-resolver refusal must NEVER cause false positive
	refused := reputation.ClassifySpamhausZen([]string{"127.255.255.254"})
	if refused.Outcome != "unavailable" {
		t.Fatalf("expected unavailable for Spamhaus refusal, got %s", refused.Outcome)
	}
	// Spamhaus PBL is residential dynamic IP, must be clean
	pbl := reputation.ClassifySpamhausZen([]string{"127.0.0.10"})
	if pbl.Outcome != "clean" || pbl.Category != "residentialPBL" {
		t.Fatalf("expected clean PBL, got %+v", pbl)
	}
	// Single non-Spamhaus hit -> caution (multi-source consensus)
	single := reputation.Synthesize("1.2.3.4", []reputation.Vote{
		reputation.ClassifySpamhausZen(nil),
		reputation.ClassifySpamhausDrop(nil),
		reputation.ClassifyTorExit(nil),
		reputation.ClassifyDroneBL(nil),
		reputation.ClassifyUCEProtect([]string{"127.0.0.2"}),
	})
	if single.Severity != "caution" || single.BlacklistHits != 1 {
		t.Fatalf("single hit must be caution, got %+v", single)
	}
	// Tor exit -> danger
	tor := reputation.Synthesize("1.2.3.4", []reputation.Vote{
		reputation.ClassifySpamhausZen(nil),
		reputation.ClassifyTorExit([]string{"127.0.0.2"}),
	})
	if tor.Severity != "danger" || !tor.IsTorExit {
		t.Fatalf("Tor exit must be danger, got %+v", tor)
	}
}

func startMockHTTPConnectServer(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				buf := make([]byte, 1024)
				for {
					n, err := br.Read(buf)
					if err != nil {
						return
					}
					_, _ = conn.Write(append([]byte("http-echo:"), buf[:n]...))
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

func startMockSOCKS5Server(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				greet := make([]byte, 3)
				if _, err := io.ReadFull(conn, greet); err != nil || greet[0] != 0x05 {
					return
				}
				_, _ = conn.Write([]byte{0x05, 0x00})
				head := make([]byte, 4)
				if _, err := io.ReadFull(conn, head); err != nil || head[0] != 0x05 || head[1] != 0x01 {
					return
				}
				if head[3] == 0x03 {
					lb := make([]byte, 1)
					_, _ = io.ReadFull(conn, lb)
					_, _ = io.CopyN(io.Discard, conn, int64(lb[0])+2)
				}
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB})
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					_, _ = conn.Write(append([]byte("s5-echo:"), buf[:n]...))
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

func sendRaw(t *testing.T, port int, req string, followUp string) (string, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, req)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	first := string(buf[:n])
	if followUp == "" {
		return first, ""
	}
	_, _ = io.WriteString(conn, followUp)
	n2, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return first, string(buf[:n2])
}

func TestCircuitBreakerHTTPAndSOCKS5AndHealth(t *testing.T) {
	tmp := t.TempDir()
	audit := proxy.NewAuditLog(tmp)

	// 1. HTTP CONNECT upstream + SSRF block + health endpoint + trip 503
	httpUpPort, stopHTTP := startMockHTTPConnectServer(t)
	defer stopHTTP()

	cb := proxy.NewCircuitBreaker(audit, nil)
	gp, err := cb.Start(17915, httpUpPort, proxy.ProtoHTTP, proxy.GateState{Open: true, ExitIP: "1.2.3.4", CountryCode: "US"})
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Stop()

	h1, _ := sendRaw(t, gp, "GET /__claude_guard_health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "")
	if !strings.HasPrefix(h1, "HTTP/1.1 200") || !strings.Contains(h1, `"state":"open"`) {
		t.Fatalf("unexpected open health: %s", h1)
	}
	ssrf, _ := sendRaw(t, gp, "CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:22\r\n\r\n", "")
	if !strings.HasPrefix(ssrf, "HTTP/1.1 403") {
		t.Fatalf("loopback must be 403, got %s", ssrf)
	}
	r1, r2 := sendRaw(t, gp, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n", "ping")
	if !strings.HasPrefix(r1, "HTTP/1.1 200") || r2 != "http-echo:ping" {
		t.Fatalf("HTTP CONNECT relay failed: %q / %q", r1, r2)
	}
	cb.SetGate(proxy.GateState{Open: false, TripReason: "Region drift"})
	tripped, _ := sendRaw(t, gp, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n", "")
	if !strings.HasPrefix(tripped, "HTTP/1.1 503") {
		t.Fatalf("tripped breaker must return 503, got %s", tripped)
	}
	h2, _ := sendRaw(t, gp, "GET /__claude_guard_health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "")
	if !strings.HasPrefix(h2, "HTTP/1.1 503") || !strings.Contains(h2, `"state":"tripped"`) {
		t.Fatalf("unexpected tripped health: %s", h2)
	}

	// 2. Pure SOCKS5 upstream bridging
	s5Port, stopS5 := startMockSOCKS5Server(t)
	defer stopS5()
	cb2 := proxy.NewCircuitBreaker(audit, nil)
	gp2, err := cb2.Start(17916, s5Port, proxy.ProtoSOCKS5, proxy.GateState{Open: true, ExitIP: "48.45.153.58", CountryCode: "US"})
	if err != nil {
		t.Fatal(err)
	}
	defer cb2.Stop()

	sr1, sr2 := sendRaw(t, gp2, "CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n", "hello-s5")
	if !strings.HasPrefix(sr1, "HTTP/1.1 200") || sr2 != "s5-echo:hello-s5" {
		t.Fatalf("SOCKS5 relay failed: %q / %q", sr1, sr2)
	}
	cb.Stop()
	cb2.Stop()
	time.Sleep(40 * time.Millisecond)
}

func TestClashMultiClientScriptsAndSettingsAndWorkbench(t *testing.T) {
	tmp := t.TempDir()
	appData := filepath.Join(tmp, "AppData")
	stateDir := filepath.Join(tmp, "State")
	home := filepath.Join(tmp, "Home")

	// 1. Clash Verge Rev custom script chaining & exact restore + Mihomo Party standalone override
	vergeDir := filepath.Join(appData, "io.github.clash-verge-rev.clash-verge-rev", "profiles")
	_ = os.MkdirAll(vergeDir, 0o755)
	_ = os.MkdirAll(filepath.Join(appData, "mihomo-party"), 0o755)
	custom := "function main(config) { config.__mine = true; return config; }\n"
	_ = os.WriteFile(filepath.Join(vergeDir, "Script.js"), []byte(custom), 0o644)

	targets := clash.InspectScriptTargets(appData, stateDir)
	chained, err := clash.InstallScript(targets[0], "US-01", stateDir)
	if err != nil || !chained {
		t.Fatalf("expected chained install, chained=%v err=%v", chained, err)
	}
	written, _ := os.ReadFile(targets[0].ScriptPath)
	if !strings.Contains(string(written), "__claudeOriginalUserMain") || !strings.Contains(string(written), "Claude-Pin") {
		t.Fatalf("written script missing chain or Claude-Pin")
	}
	if err := clash.RestoreScript(targets[0], stateDir); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(targets[0].ScriptPath)
	if string(restored) != custom {
		t.Fatalf("exact restore mismatch: %q", string(restored))
	}

	// Mihomo Party standalone override
	if _, err := clash.InstallScript(targets[2], "JP-01", stateDir); err != nil {
		t.Fatal(err)
	}
	if err := clash.RestoreScript(targets[2], stateDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(targets[2].ScriptPath); !os.IsNotExist(err) {
		t.Fatal("standalone override must be removed on restore")
	}

	// 2. Claude settings.json atomic backup & restore preserving user keys
	settingsPath := diagnostics.ClaudeSettingsPath(home)
	_ = os.MkdirAll(filepath.Dir(settingsPath), 0o700)
	_ = os.WriteFile(settingsPath, []byte(`{"env":{"USER_KEY":"keep","TZ":"Asia/Shanghai"}}`), 0o600)
	if err := diagnostics.ApplyGuardSettings(home, stateDir, 17899, 7897, map[string]string{"TZ": "America/New_York", "LANG": "en_US.UTF-8"}); err != nil {
		t.Fatal(err)
	}
	px, tz := diagnostics.ReadConfiguredProcessEnv(home)
	if px != "http://127.0.0.1:17899" || tz != "America/New_York" {
		t.Fatalf("unexpected applied env: proxy=%q tz=%q", px, tz)
	}
	if err := diagnostics.RestoreGuardSettings(home, stateDir); err != nil {
		t.Fatal(err)
	}
	rawAfter, _ := os.ReadFile(settingsPath)
	var afterObj map[string]map[string]string
	_ = json.Unmarshal(rawAfter, &afterObj)
	if afterObj["env"]["USER_KEY"] != "keep" || afterObj["env"]["TZ"] != "Asia/Shanghai" || afterObj["env"]["HTTPS_PROXY"] != "" {
		t.Fatalf("restore corrupted settings: %+v", afterObj)
	}

	// 3. Isolated browser spec (no --host-resolver-rules infobar!) & Preferences language merge
	spec := workbench.BuildBrowserLaunchSpec(workbench.BrowserInfo{ID: "chrome", Name: "Chrome", ExecutablePath: "chrome.exe"}, stateDir, 17899, "US", "America/New_York", "https://claude.ai")
	joinedArgs := strings.Join(spec.Arguments, " ")
	if strings.Contains(joinedArgs, "--host-resolver-rules") || !strings.Contains(joinedArgs, "--proxy-server=http://127.0.0.1:17899") {
		t.Fatalf("unexpected browser args: %v", spec.Arguments)
	}
	if err := workbench.ApplyProfileLanguagePreferences(spec.ProfileDir, "en-US"); err != nil {
		t.Fatal(err)
	}
	prefBytes, _ := os.ReadFile(filepath.Join(spec.ProfileDir, "Default", "Preferences"))
	if !strings.Contains(string(prefBytes), `"accept_languages":"en-US,en"`) {
		t.Fatalf("Preferences missing accept_languages: %s", string(prefBytes))
	}

	// 4. Windows claude-safe.cmd wrapper install / uninstall
	if workbench.IsShellGuardInstalled(home) {
		t.Fatal("should not be installed initially")
	}
	cmdPath, err := workbench.InstallShellGuard(home)
	if err != nil || !workbench.IsShellGuardInstalled(home) {
		t.Fatalf("install shell guard failed: %s %v", cmdPath, err)
	}
	if err := workbench.UninstallShellGuard(home); err != nil || workbench.IsShellGuardInstalled(home) {
		t.Fatalf("uninstall shell guard failed: %v", err)
	}
}
