package webui

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/clipsone/claude-env-check/windows/internal/clash"
	"github.com/clipsone/claude-env-check/windows/internal/diagnostics"
	"github.com/clipsone/claude-env-check/windows/internal/proxy"
	"github.com/clipsone/claude-env-check/windows/internal/regions"
	"github.com/clipsone/claude-env-check/windows/internal/tray"
	"github.com/clipsone/claude-env-check/windows/internal/workbench"
)

//go:embed index.html
var indexHTML string

type GuardStatus struct {
	Running             bool                   `json:"running"`
	Tripped             bool                   `json:"tripped"`
	GuardPort           int                    `json:"guardPort"`
	UpstreamPort        int                    `json:"upstreamPort"`
	DetectedPort        int                    `json:"detectedPort"`
	UpstreamProtocol    proxy.UpstreamProtocol `json:"upstreamProtocol"`
	StrictIPLock        bool                   `json:"strictIPLock"`
	InjectLocale        bool                   `json:"injectLocale"`
	ProcessTZ           string                 `json:"processTZ,omitempty"`
	LastVerifiedIP      string                 `json:"lastVerifiedIP,omitempty"`
	LastVerifiedCountry string                 `json:"lastVerifiedCountry,omitempty"`
	ActiveTunnels       int                    `json:"activeTunnels"`
	Note                string                 `json:"note,omitempty"`
	Error               string                 `json:"error,omitempty"`
}

type Engine struct {
	mu       sync.Mutex
	home     string
	appData  string
	stateDir string

	audit   *proxy.AuditLog
	history *diagnostics.ExitHistoryStore
	breaker *proxy.CircuitBreaker

	snapshot      diagnostics.Snapshot
	clients       []clash.DiscoveredClient
	clashEP       *clash.ControllerEndpoint
	clashSnap     *clash.ControllerSnapshot
	scriptTargets []clash.ScriptTarget
	browsers      []workbench.BrowserInfo
	desktopExe    string

	guard         GuardStatus
	pinnedCountry string
	pinnedIP      string
	lastRouteLeaf string
	lastRouteMode string
	stopWatchCh   chan struct{}
	token         string
	baseURL       string
	httpServer    *http.Server
}

func NewEngine() *Engine {
	home, _ := os.UserHomeDir()
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	stateDir := filepath.Join(appData, "ClaudeEnvironmentCheck")
	_ = os.MkdirAll(stateDir, 0o700)

	var tb [16]byte
	_, _ = rand.Read(tb[:])
	token := hex.EncodeToString(tb[:])

	e := &Engine{
		home:     home,
		appData:  appData,
		stateDir: stateDir,
		audit:    proxy.NewAuditLog(stateDir),
		history:  diagnostics.NewExitHistoryStore(stateDir),
		token:    token,
		guard:    GuardStatus{InjectLocale: true, UpstreamProtocol: proxy.ProtoHTTP},
	}
	e.breaker = proxy.NewCircuitBreaker(e.audit, func(reason string) {
		e.RecheckGuard(false)
	})
	e.RefreshSymbiosis()
	e.browsers = workbench.DiscoverWindowsBrowsers()
	e.desktopExe = workbench.DiscoverClaudeDesktopExe()
	e.Scan(false)
	return e
}

func (e *Engine) StartHTTPServer() (string, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	e.baseURL = "http://" + ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/", e.handleIndex)
	mux.HandleFunc("/api/state", e.auth(e.handleState))
	mux.HandleFunc("/api/scan", e.auth(e.handleScan))
	mux.HandleFunc("/api/guard/start", e.auth(e.handleGuardStart))
	mux.HandleFunc("/api/guard/stop", e.auth(e.handleGuardStop))
	mux.HandleFunc("/api/guard/recheck", e.auth(e.handleGuardRecheck))
	mux.HandleFunc("/api/guard/trip", e.auth(e.handleGuardTrip))
	mux.HandleFunc("/api/symbiosis/refresh", e.auth(e.handleSymbiosisRefresh))
	mux.HandleFunc("/api/script/install", e.auth(e.handleScriptInstall))
	mux.HandleFunc("/api/script/restore", e.auth(e.handleScriptRestore))
	mux.HandleFunc("/api/clash/close", e.auth(e.handleClashClose))
	mux.HandleFunc("/api/workbench/browser", e.auth(e.handleWorkbenchBrowser))
	mux.HandleFunc("/api/workbench/desktop", e.auth(e.handleWorkbenchDesktop))
	mux.HandleFunc("/api/workbench/shell", e.auth(e.handleWorkbenchShell))
	mux.HandleFunc("/api/workbench/autostart", e.auth(e.handleWorkbenchAutoStart))
	mux.HandleFunc("/api/history/clear", e.auth(e.handleClearHistory))
	mux.HandleFunc("/api/audit/clear", e.auth(e.handleClearAudit))
	mux.HandleFunc("/api/audit/csv", e.handleAuditCSV)

	e.httpServer = &http.Server{Handler: mux}
	go func() { _ = e.httpServer.Serve(ln) }()
	return e.baseURL, nil
}

func (e *Engine) BaseURL() string { return e.baseURL }

func (e *Engine) Shutdown() {
	e.StopGuard()
	if e.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = e.httpServer.Shutdown(ctx)
	}
}

func (e *Engine) AutoStartGuardIfReady() {
	for i := 0; i < 10; i++ {
		e.RefreshSymbiosis()
		e.mu.Lock()
		port := e.guard.DetectedPort
		running := e.guard.Running
		e.mu.Unlock()
		if running {
			return
		}
		if port > 0 {
			if err := e.StartGuard(port, true, false); err == nil {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func (e *Engine) Scan(online bool) {
	e.mu.Lock()
	gPort := e.guard.GuardPort
	running := e.guard.Running
	e.mu.Unlock()

	port := 0
	route := "系统网络路径"
	if running && gPort > 0 {
		port = gPort
		route = fmt.Sprintf("保护代理 127.0.0.1:%d", gPort)
	}
	snap := diagnostics.Capture(context.Background(), online, port, proxy.ProtoHTTP, route, e.history, e.home)
	e.mu.Lock()
	e.snapshot = snap
	e.mu.Unlock()
}

func (e *Engine) RefreshSymbiosis() {
	clients := clash.ScanRunningClients(e.appData)
	eps := clash.DiscoverControllers(e.appData)
	var snap *clash.ControllerSnapshot
	var activeEP *clash.ControllerEndpoint
	for i := range eps {
		if s, err := clash.FetchSnapshot(eps[i]); err == nil {
			snap = s
			epCopy := eps[i]
			activeEP = &epCopy
			break
		}
	}
	targets := clash.InspectScriptTargets(e.appData, e.stateDir)

	e.mu.Lock()
	e.clients = clients
	e.clashSnap = snap
	e.clashEP = activeEP
	e.scriptTargets = targets
	if e.guard.DetectedPort == 0 {
		if len(clients) > 0 {
			e.guard.DetectedPort = clients[0].Port
		} else if snap != nil && snap.MixedPort > 0 {
			e.guard.DetectedPort = snap.MixedPort
		}
	}
	e.mu.Unlock()
}

func (e *Engine) StartGuard(upstreamPort int, injectLocale, strictIPLock bool) error {
	if upstreamPort <= 0 {
		e.mu.Lock()
		upstreamPort = e.guard.DetectedPort
		e.mu.Unlock()
	}
	if upstreamPort < 1 || upstreamPort > 65535 {
		return fmt.Errorf("未检测到有效上游代理端口，请手动输入（如 7897）")
	}

	httpOK, socksOK := clash.ProbePortProtocols(upstreamPort)
	if !httpOK && !socksOK {
		return fmt.Errorf("无法连接到本地上游代理 127.0.0.1:%d", upstreamPort)
	}
	proto := proxy.ProtoHTTP
	if !httpOK && socksOK {
		proto = proxy.ProtoSOCKS5
	}

	apiCode, _, err := diagnostics.ProbeClaudeAPI(upstreamPort, proto)
	if err != nil {
		return fmt.Errorf("经 127.0.0.1:%d 访问 Claude API 失败: %w", upstreamPort, err)
	}
	geo := diagnostics.ProbeMultiSourceGeo(upstreamPort, proto)
	if geo.PrimaryIP == "" || geo.PrimaryCountry == "" {
		return fmt.Errorf("无法通过 127.0.0.1:%d 核验公网出口地区", upstreamPort)
	}
	if geo.Split {
		return fmt.Errorf("多源出口国家不一致（%s），请先固定分流规则", strings.Join(geo.SplitCountries, " / "))
	}
	if regions.Support(geo.PrimaryCountry) != regions.Supported {
		return fmt.Errorf("出口位于不支持地区 %s，已拒绝启动", regions.DisplayName(geo.PrimaryCountry))
	}

	extraEnv := map[string]string{}
	if injectLocale {
		loc := regions.RecommendedProcessLocale(geo.PrimaryCountry, geo.PrimaryTZ)
		extraEnv["TZ"] = loc.TimeZone
		extraEnv["LANG"] = loc.Lang
		extraEnv["LC_ALL"] = loc.Lang
	}

	bound, err := e.breaker.Start(17899, upstreamPort, proto, proxy.GateState{
		Open: true, ExitIP: geo.PrimaryIP, CountryCode: geo.PrimaryCountry,
	})
	if err != nil {
		return err
	}
	if err := diagnostics.ApplyGuardSettings(e.home, e.stateDir, bound, upstreamPort, extraEnv); err != nil {
		e.breaker.Stop()
		return err
	}

	e.mu.Lock()
	e.guard.Running = true
	e.guard.Tripped = false
	e.guard.GuardPort = bound
	e.guard.UpstreamPort = upstreamPort
	e.guard.UpstreamProtocol = proto
	e.guard.InjectLocale = injectLocale
	e.guard.StrictIPLock = strictIPLock
	e.guard.ProcessTZ = extraEnv["TZ"]
	e.guard.LastVerifiedIP = geo.PrimaryIP
	e.guard.LastVerifiedCountry = geo.PrimaryCountry
	e.guard.Error = ""
	e.guard.Note = fmt.Sprintf("熔断守卫已启动：127.0.0.1:%d → %s:%d（%s · HTTP %d）", bound, proto, upstreamPort, regions.DisplayName(geo.PrimaryCountry), apiCode)
	e.pinnedCountry = geo.PrimaryCountry
	e.pinnedIP = geo.PrimaryIP
	if e.clashSnap != nil {
		e.lastRouteLeaf = e.clashSnap.LeafNode
		e.lastRouteMode = e.clashSnap.Mode
	}
	if e.stopWatchCh != nil {
		close(e.stopWatchCh)
	}
	stopCh := make(chan struct{})
	e.stopWatchCh = stopCh
	e.mu.Unlock()

	tray.UpdateTooltip(fmt.Sprintf("Claude 环境体检 · 护卫中 (%s %s)", geo.PrimaryCountry, geo.PrimaryIP))
	go e.runWatchdogs(stopCh)
	return nil
}

func (e *Engine) StopGuard() {
	e.mu.Lock()
	if e.stopWatchCh != nil {
		close(e.stopWatchCh)
		e.stopWatchCh = nil
	}
	e.guard.Running = false
	e.guard.Tripped = false
	e.guard.GuardPort = 0
	e.guard.ProcessTZ = ""
	e.guard.Note = "已关闭熔断守卫并恢复 ~/.claude/settings.json。"
	e.guard.Error = ""
	e.mu.Unlock()

	e.breaker.Stop()
	_ = diagnostics.RestoreGuardSettings(e.home, e.stateDir)
	tray.UpdateTooltip("Claude 环境体检 · 未开启守卫")
}

func (e *Engine) ManualTrip() {
	e.trip("用户手动触发熔断阻断")
}

func (e *Engine) trip(reason string) {
	e.breaker.SetGate(proxy.GateState{Open: false, TripReason: reason})
	e.mu.Lock()
	e.guard.Tripped = true
	e.guard.Error = reason
	e.guard.Note = ""
	e.mu.Unlock()
	tray.UpdateTooltip("Claude 环境体检 · 已熔断: " + reason)
}

func (e *Engine) RecheckGuard(acceptNewIP bool) {
	e.mu.Lock()
	if !e.guard.Running {
		e.mu.Unlock()
		return
	}
	upPort := e.guard.UpstreamPort
	proto := e.guard.UpstreamProtocol
	strictIP := e.guard.StrictIPLock
	pinnedIP := e.pinnedIP
	e.mu.Unlock()

	geo := diagnostics.ProbeMultiSourceGeo(upPort, proto)
	if geo.PrimaryIP != "" {
		e.history.Record(diagnostics.ExitSample{
			CapturedAt: time.Now(), IP: geo.PrimaryIP, CountryCode: geo.PrimaryCountry,
			ASN: geo.ASN, Org: geo.Org, NetworkKind: geo.NetworkKind,
			ProbePath: fmt.Sprintf("熔断守卫 127.0.0.1:%d", upPort),
		})
	}
	if geo.PrimaryIP == "" || geo.PrimaryCountry == "" {
		e.trip("上游代理掉线或无法获取出口 IP")
		return
	}
	if geo.Split {
		e.trip("多源出口国家冲突：" + strings.Join(geo.SplitCountries, " / "))
		return
	}
	if regions.Support(geo.PrimaryCountry) != regions.Supported {
		e.trip("出口漂移至不支持地区：" + regions.DisplayName(geo.PrimaryCountry))
		return
	}
	if strictIP && pinnedIP != "" && pinnedIP != geo.PrimaryIP && !acceptNewIP {
		e.trip(fmt.Sprintf("严格锁 IP 已触发：%s → %s", pinnedIP, geo.PrimaryIP))
		return
	}

	e.breaker.SetGate(proxy.GateState{Open: true, ExitIP: geo.PrimaryIP, CountryCode: geo.PrimaryCountry})
	e.mu.Lock()
	e.guard.Tripped = false
	e.guard.LastVerifiedIP = geo.PrimaryIP
	e.guard.LastVerifiedCountry = geo.PrimaryCountry
	e.guard.Error = ""
	e.guard.Note = fmt.Sprintf("复检通过（%s · %s），已放行 Claude。", regions.DisplayName(geo.PrimaryCountry), geo.PrimaryIP)
	if acceptNewIP || e.pinnedIP == "" {
		e.pinnedIP = geo.PrimaryIP
		e.pinnedCountry = geo.PrimaryCountry
	}
	e.mu.Unlock()
	tray.UpdateTooltip(fmt.Sprintf("Claude 环境体检 · 护卫中 (%s %s)", geo.PrimaryCountry, geo.PrimaryIP))
}

func (e *Engine) runWatchdogs(stopCh chan struct{}) {
	t30 := time.NewTicker(30 * time.Second)
	t2 := time.NewTicker(2 * time.Second)
	defer t30.Stop()
	defer t2.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-t30.C:
			e.RecheckGuard(false)
		case <-t2.C:
			e.mu.Lock()
			ep := e.clashEP
			prevLeaf := e.lastRouteLeaf
			prevMode := e.lastRouteMode
			e.mu.Unlock()
			if ep == nil {
				continue
			}
			snap, err := clash.FetchSnapshot(*ep)
			if err != nil {
				continue
			}
			if prevLeaf != "" && (snap.LeafNode != prevLeaf || snap.Mode != prevMode) {
				e.mu.Lock()
				e.lastRouteLeaf = snap.LeafNode
				e.lastRouteMode = snap.Mode
				e.clashSnap = snap
				e.mu.Unlock()
				e.trip(fmt.Sprintf("检测到 Clash 节点变动（%s → %s），已秒级预熔断并复检中…", prevLeaf, snap.LeafNode))
				go e.RecheckGuard(false)
			}
		}
	}
}

func (e *Engine) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Guard-Token") != e.token {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (e *Engine) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(indexHTML, "__GUARD_TOKEN__", e.token)))
}

func (e *Engine) handleState(w http.ResponseWriter, r *http.Request) {
	stats, recent := e.audit.Snapshot(100)
	hist := e.history.Summary()

	e.mu.Lock()
	g := e.guard
	g.ActiveTunnels = e.breaker.ActiveTunnels()
	payload := map[string]any{
		"snapshot":            e.snapshot,
		"guard":               g,
		"clients":             e.clients,
		"clash":               e.clashSnap,
		"scriptTargets":       e.scriptTargets,
		"browsers":            e.browsers,
		"desktopExe":          e.desktopExe,
		"shellGuardInstalled": workbench.IsShellGuardInstalled(e.home),
		"autoStart":           workbench.IsAutoStartEnabled(),
		"audit":               map[string]any{"stats": stats, "recent": recent},
		"history":             hist,
	}
	e.mu.Unlock()
	writeJSON(w, http.StatusOK, payload)
}

func (e *Engine) handleScan(w http.ResponseWriter, r *http.Request) {
	var body struct{ Online bool `json:"online"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	e.Scan(body.Online)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleGuardStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UpstreamPort int  `json:"upstreamPort"`
		InjectLocale bool `json:"injectLocale"`
		StrictIPLock bool `json:"strictIPLock"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := e.StartGuard(body.UpstreamPort, body.InjectLocale, body.StrictIPLock); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleGuardStop(w http.ResponseWriter, r *http.Request) {
	e.StopGuard()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleGuardRecheck(w http.ResponseWriter, r *http.Request) {
	var body struct{ AcceptNewIP bool `json:"acceptNewIP"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	e.RecheckGuard(body.AcceptNewIP)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleGuardTrip(w http.ResponseWriter, r *http.Request) {
	e.ManualTrip()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleSymbiosisRefresh(w http.ResponseWriter, r *http.Request) {
	e.RefreshSymbiosis()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleScriptInstall(w http.ResponseWriter, r *http.Request) {
	var body struct{ TargetID string `json:"targetID"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	for _, t := range clash.InspectScriptTargets(e.appData, e.stateDir) {
		if t.ID == body.TargetID {
			e.mu.Lock()
			pref := ""
			if e.clashSnap != nil {
				pref = e.clashSnap.LeafNode
			}
			e.mu.Unlock()
			chained, err := clash.InstallScript(t, pref, e.stateDir)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			e.RefreshSymbiosis()
			extra := ""
			if chained {
				extra = "（已自动保留并串联原自定义脚本）"
			}
			writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("已一键写入 %s%s。%s", t.DisplayName, extra, t.ReloadHint)})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知客户端目标"})
}

func (e *Engine) handleScriptRestore(w http.ResponseWriter, r *http.Request) {
	var body struct{ TargetID string `json:"targetID"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	for _, t := range clash.InspectScriptTargets(e.appData, e.stateDir) {
		if t.ID == body.TargetID {
			if err := clash.RestoreScript(t, e.stateDir); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			e.RefreshSymbiosis()
			writeJSON(w, http.StatusOK, map[string]string{"message": "已无损还原 " + t.DisplayName + " 原始脚本。"})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "未知客户端目标"})
}

func (e *Engine) handleClashClose(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID string `json:"id"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	e.mu.Lock()
	ep := e.clashEP
	e.mu.Unlock()
	if ep != nil && body.ID != "" {
		_ = clash.CloseConnection(*ep, body.ID)
		e.RefreshSymbiosis()
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleWorkbenchBrowser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BrowserID string `json:"browserID"`
		StartURL  string `json:"startURL"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	e.mu.Lock()
	var chosen *workbench.BrowserInfo
	for i := range e.browsers {
		if e.browsers[i].ID == body.BrowserID {
			chosen = &e.browsers[i]
			break
		}
	}
	if chosen == nil && len(e.browsers) > 0 {
		chosen = &e.browsers[0]
	}
	port := e.guard.GuardPort
	if port == 0 {
		port = e.guard.DetectedPort
	}
	cc := e.guard.LastVerifiedCountry
	if cc == "" {
		cc = e.snapshot.ObservedExitCountry
	}
	tz := e.snapshot.ObservedExitTZ
	e.mu.Unlock()

	if chosen == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "未检测到 Chrome / Edge / Brave / Vivaldi"})
		return
	}
	spec := workbench.BuildBrowserLaunchSpec(*chosen, e.stateDir, port, cc, tz, body.StartURL)
	if err := workbench.LaunchBrowser(spec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已启动隔离 " + chosen.Name + "（无提示横幅 · 禁 QUIC · 防 WebRTC · 独立目录）。"})
}

func (e *Engine) handleWorkbenchDesktop(w http.ResponseWriter, r *http.Request) {
	var body struct{ Isolated bool `json:"isolated"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	e.mu.Lock()
	exe := e.desktopExe
	port := e.guard.GuardPort
	if port == 0 {
		port = e.guard.DetectedPort
	}
	cc := e.guard.LastVerifiedCountry
	if cc == "" {
		cc = e.snapshot.ObservedExitCountry
	}
	tz := e.snapshot.ObservedExitTZ
	e.mu.Unlock()
	if err := workbench.LaunchClaudeDesktopAligned(exe, e.stateDir, port, cc, tz, body.Isolated); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已对齐环境启动 Windows 版 Claude Desktop（Chromium 渲染层与 Node 主进程均走本地守卫）。"})
}

func (e *Engine) handleWorkbenchShell(w http.ResponseWriter, r *http.Request) {
	var body struct{ Install bool `json:"install"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Install {
		p, err := workbench.InstallShellGuard(e.home)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "已安装终端防漏安全壳至 " + p + "（将 %USERPROFILE%\\.local\\bin 加入 PATH 后直接运行 claude-safe）。"})
		return
	}
	if err := workbench.UninstallShellGuard(e.home); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已卸载 claude-safe.cmd。"})
}

func (e *Engine) handleWorkbenchAutoStart(w http.ResponseWriter, r *http.Request) {
	var body struct{ Enabled bool `json:"enabled"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := workbench.SetAutoStartEnabled(body.Enabled); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleClearHistory(w http.ResponseWriter, r *http.Request) {
	e.history.Clear()
	e.Scan(e.snapshot.Online)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleClearAudit(w http.ResponseWriter, r *http.Request) {
	e.audit.Clear()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleAuditCSV(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != e.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="claude-env-audit.csv"`)
	_, _ = w.Write([]byte(e.audit.ExportCSV()))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
