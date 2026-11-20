package clash

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ManagedMarkerStart = "// [CLAUDE-ENV-CHECK-MANAGED-START]"
	ManagedMarkerEnd   = "// [CLAUDE-ENV-CHECK-MANAGED-END]"
)

type DiscoveredClient struct {
	ClientName   string `json:"clientName"`
	Port         int    `json:"port"`
	SupportsHTTP bool   `json:"supportsHTTP"`
	SupportsS5   bool   `json:"supportsSOCKS5"`
	Label        string `json:"label"`
}

type ControllerEndpoint struct {
	ClientName string `json:"clientName"`
	BaseURL    string `json:"baseURL"`
	Secret     string `json:"-"`
	MixedPort  int    `json:"mixedPort,omitempty"`
}

type ActiveConnection struct {
	ID          string   `json:"id"`
	Host        string   `json:"host"`
	Port        string   `json:"port"`
	Network     string   `json:"network"`
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rulePayload"`
	Chains      []string `json:"chains"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	IsViolation bool     `json:"isViolation"`
}

type ControllerSnapshot struct {
	ClientName        string             `json:"clientName"`
	BaseURL           string             `json:"baseURL"`
	KernelVersion     string             `json:"kernelVersion"`
	Mode              string             `json:"mode"`
	TunEnabled        bool               `json:"tunEnabled"`
	MixedPort         int                `json:"mixedPort"`
	LeafNode          string             `json:"leafNode"`
	RouteChain        []string           `json:"routeChain"`
	MatchedRule       string             `json:"matchedRule"`
	IsDirect          bool               `json:"isDirect"`
	HasDynamicGroup   bool               `json:"hasDynamicGroup"`
	DynamicGroups     []string           `json:"dynamicGroups"`
	HasClaudePin      bool               `json:"hasClaudePin"`
	ClaudeConnections []ActiveConnection `json:"claudeConnections"`
	DirectViolations  []ActiveConnection `json:"directViolations"`
	TotalConnections  int                `json:"totalConnections"`
}

type ScriptTarget struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	ConfigDir      string `json:"configDir"`
	ScriptPath     string `json:"scriptPath"`
	BackupFileName string `json:"backupFileName"`
	Standalone     bool   `json:"standalone"`
	Installed      bool   `json:"installed"`
	ScriptActive   bool   `json:"scriptActive"`
	HasCustom      bool   `json:"hasCustom"`
	ChainedCustom  bool   `json:"chainedCustom"`
	ReloadHint     string `json:"reloadHint"`
}

type scriptBackup struct {
	Version             int       `json:"version"`
	TargetPath          string    `json:"targetPath"`
	HadFile             bool      `json:"hadFile"`
	OriginalBase64      string    `json:"originalBase64"`
	ChainedCustomScript bool      `json:"chainedCustomScript"`
	SavedAt             time.Time `json:"savedAt"`
}

func defaultAppDataDir() string {
	if v := os.Getenv("APPDATA"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Roaming")
}

func KnownScriptTargets(appData string) []ScriptTarget {
	if appData == "" {
		appData = defaultAppDataDir()
	}
	return []ScriptTarget{
		{
			ID: "clash-verge-rev", DisplayName: "Clash Verge Rev",
			ConfigDir: filepath.Join(appData, "io.github.clash-verge-rev.clash-verge-rev"),
			ScriptPath: filepath.Join(appData, "io.github.clash-verge-rev.clash-verge-rev", "profiles", "Script.js"),
			BackupFileName: "clash-verge-script-backup.json",
			ReloadHint: "打开 Clash Verge Rev → 订阅页点击当前订阅刷新即可生效。",
		},
		{
			ID: "clash-verge-legacy", DisplayName: "Clash Verge (旧版)",
			ConfigDir: filepath.Join(appData, "io.github.zzzgydi.clash-verge"),
			ScriptPath: filepath.Join(appData, "io.github.zzzgydi.clash-verge", "profiles", "Script.js"),
			BackupFileName: "clash-verge-legacy-script-backup.json",
			ReloadHint: "打开 Clash Verge → 订阅页重载当前配置即可生效。",
		},
		{
			ID: "mihomo-party", DisplayName: "Mihomo Party",
			ConfigDir: filepath.Join(appData, "mihomo-party"),
			ScriptPath: filepath.Join(appData, "mihomo-party", "override", "claude-env-guard.js"),
			BackupFileName: "mihomo-party-script-backup.json",
			Standalone: true,
			ReloadHint: "打开 Mihomo Party → 覆写页勾选启用 claude-env-guard.js 并重载订阅。",
		},
		{
			ID: "flclash", DisplayName: "FlClash",
			ConfigDir: filepath.Join(appData, "com.follow.clash"),
			ScriptPath: filepath.Join(appData, "com.follow.clash", "claude-env-override.js"),
			BackupFileName: "flclash-script-backup.json",
			Standalone: true,
			ReloadHint: "打开 FlClash → 脚本/覆写页导入 claude-env-override.js 即可生效。",
		},
	}
}

func InspectScriptTargets(appData, stateDir string) []ScriptTarget {
	targets := KnownScriptTargets(appData)
	for i := range targets {
		t := &targets[i]
		if fi, err := os.Stat(t.ConfigDir); err == nil && fi.IsDir() {
			t.Installed = true
			data, _ := os.ReadFile(t.ScriptPath)
			txt := string(data)
			if strings.Contains(txt, ManagedMarkerStart) {
				t.ScriptActive = true
				if b, err := readBackup(filepath.Join(stateDir, t.BackupFileName)); err == nil && b != nil {
					t.ChainedCustom = b.ChainedCustomScript
				}
			} else if strings.TrimSpace(txt) != "" && !IsDefaultStubScript(txt) {
				t.HasCustom = true
			}
		}
	}
	return targets
}

// ProbePortProtocols independently checks HTTP CONNECT (200/407) and RFC 1928 SOCKS5 on 127.0.0.1:port.
func ProbePortProtocols(port int) (httpOK, socks5OK bool) {
	httpOK = probeHTTPConnect(port)
	socks5OK = probeSOCKS5(port)
	return
}

func probeHTTPConnect(port int) bool {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 350*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(450 * time.Millisecond))
	_, _ = io.WriteString(conn, "CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n")
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return false
	}
	line := string(buf[:n])
	return strings.HasPrefix(line, "HTTP/1.1 200") || strings.HasPrefix(line, "HTTP/1.0 200") ||
		strings.HasPrefix(line, "HTTP/1.1 407") || strings.HasPrefix(line, "HTTP/1.0 407")
}

func probeSOCKS5(port int) bool {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 350*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(450 * time.Millisecond))
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	return reply[0] == 0x05 && (reply[1] == 0x00 || reply[1] == 0x02)
}

func ScanRunningClients(appData string) []DiscoveredClient {
	type cand struct {
		name string
		port int
	}
	seen := map[int]bool{}
	var candidates []cand
	add := func(name string, p int) {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			candidates = append(candidates, cand{name, p})
		}
	}

	for _, ep := range DiscoverControllers(appData) {
		if ep.MixedPort > 0 {
			add(ep.ClientName, ep.MixedPort)
		}
	}
	// Well-known Windows proxy ports
	add("Clash Verge Rev / Mihomo", 7897)
	add("Clash / Mihomo Party", 7890)
	add("FlClash", 7890)
	add("v2rayN (HTTP)", 10809)
	add("v2rayN (SOCKS5)", 10808)
	add("Hiddify / Sing-box", 12334)
	add("Sing-box / SOCKS5", 1080)
	add("ClashX / Proxy", 7891)

	var found []DiscoveredClient
	for _, c := range candidates {
		h, s := ProbePortProtocols(c.port)
		if !h && !s {
			continue
		}
		label := "HTTP"
		if h && s {
			label = "HTTP + SOCKS5"
		} else if s {
			label = "SOCKS5"
		}
		found = append(found, DiscoveredClient{
			ClientName:   c.name,
			Port:         c.port,
			SupportsHTTP: h,
			SupportsS5:   s,
			Label:        label,
		})
	}
	return found
}

var (
	reExtCtl    = regexp.MustCompile(`(?m)^\s*external-controller\s*:\s*['"]?([^'"#\r\n]+)['"]?`)
	reSecret    = regexp.MustCompile(`(?m)^\s*secret\s*:\s*['"]?([^'"#\r\n]*)['"]?`)
	reMixedPort = regexp.MustCompile(`(?m)^\s*(?:mixed-port|verge_mixed_port)\s*:\s*([0-9]{2,5})`)
)

func DiscoverControllers(appData string) []ControllerEndpoint {
	if appData == "" {
		appData = defaultAppDataDir()
	}
	sources := []struct {
		name  string
		files []string
	}{
		{"Clash Verge Rev", []string{
			filepath.Join(appData, "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml"),
			filepath.Join(appData, "io.github.clash-verge-rev.clash-verge-rev", "verge.yaml"),
			filepath.Join(appData, "io.github.clash-verge-rev.clash-verge-rev", "config.yaml"),
		}},
		{"Mihomo Party", []string{
			filepath.Join(appData, "mihomo-party", "config.yaml"),
			filepath.Join(appData, "mihomo-party", "work", "config.yaml"),
		}},
		{"FlClash", []string{
			filepath.Join(appData, "com.follow.clash", "config.yaml"),
		}},
	}

	seen := map[string]bool{}
	var eps []ControllerEndpoint
	for _, src := range sources {
		var hostPort, secret string
		var mixed int
		for _, f := range src.files {
			raw, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			txt := string(raw)
			if hostPort == "" {
				if m := reExtCtl.FindStringSubmatch(txt); len(m) == 2 {
					hostPort = strings.TrimSpace(m[1])
				}
			}
			if secret == "" {
				if m := reSecret.FindStringSubmatch(txt); len(m) == 2 {
					secret = strings.TrimSpace(m[1])
				}
			}
			if mixed == 0 {
				if m := reMixedPort.FindStringSubmatch(txt); len(m) == 2 {
					mixed, _ = strconv.Atoi(m[1])
				}
			}
		}
		if hostPort != "" {
			if strings.HasPrefix(hostPort, ":") {
				hostPort = "127.0.0.1" + hostPort
			}
			hostPort = strings.Replace(hostPort, "0.0.0.0:", "127.0.0.1:", 1)
			base := "http://" + hostPort
			if !seen[base] {
				seen[base] = true
				eps = append(eps, ControllerEndpoint{ClientName: src.name, BaseURL: base, Secret: secret, MixedPort: mixed})
			}
		}
	}
	for _, fallback := range []string{"http://127.0.0.1:9097", "http://127.0.0.1:9090"} {
		if !seen[fallback] {
			seen[fallback] = true
			eps = append(eps, ControllerEndpoint{ClientName: "Clash / Mihomo", BaseURL: fallback})
		}
	}
	return eps
}

func controllerRequest(ep ControllerEndpoint, method, path string, body []byte) ([]byte, error) {
	c := &http.Client{Timeout: 2500 * time.Millisecond}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, strings.TrimRight(ep.BaseURL, "/")+path, reader)
	if err != nil {
		return nil, err
	}
	if ep.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+ep.Secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func FetchSnapshot(ep ControllerEndpoint) (*ControllerSnapshot, error) {
	verRaw, err := controllerRequest(ep, http.MethodGet, "/version", nil)
	if err != nil {
		return nil, err
	}
	var verObj struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(verRaw, &verObj)

	cfgRaw, _ := controllerRequest(ep, http.MethodGet, "/configs", nil)
	var cfgObj struct {
		Mode      string `json:"mode"`
		MixedPort int    `json:"mixed-port"`
		Tun       struct {
			Enable bool `json:"enable"`
		} `json:"tun"`
	}
	_ = json.Unmarshal(cfgRaw, &cfgObj)

	proxiesRaw, _ := controllerRequest(ep, http.MethodGet, "/proxies", nil)
	var proxiesWrap struct {
		Proxies map[string]struct {
			Type string `json:"type"`
			Now  string `json:"now"`
		} `json:"proxies"`
	}
	_ = json.Unmarshal(proxiesRaw, &proxiesWrap)

	rulesRaw, _ := controllerRequest(ep, http.MethodGet, "/rules", nil)
	var rulesWrap struct {
		Rules []struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
			Proxy   string `json:"proxy"`
		} `json:"rules"`
	}
	_ = json.Unmarshal(rulesRaw, &rulesWrap)

	// Match api.anthropic.com rule
	matchedRule := "MATCH"
	entryProxy := "PROXY"
	if strings.EqualFold(cfgObj.Mode, "direct") {
		matchedRule = "MODE=DIRECT"
		entryProxy = "DIRECT"
	} else if strings.EqualFold(cfgObj.Mode, "global") {
		matchedRule = "MODE=GLOBAL"
		entryProxy = "GLOBAL"
	} else {
		for _, r := range rulesWrap.Rules {
			t := strings.ToUpper(r.Type)
			p := strings.ToLower(r.Payload)
			if (t == "DOMAIN" && p == "api.anthropic.com") ||
				(t == "DOMAIN-SUFFIX" && (p == "anthropic.com" || strings.HasSuffix("api.anthropic.com", "."+p))) ||
				(t == "DOMAIN-KEYWORD" && strings.Contains("api.anthropic.com", p)) ||
				t == "MATCH" {
				matchedRule = fmt.Sprintf("%s,%s", r.Type, r.Payload)
				entryProxy = r.Proxy
				break
			}
		}
	}

	// Follow proxy chain
	var chain []string
	var dynGroups []string
	visited := map[string]bool{}
	cur := entryProxy
	for cur != "" && !visited[cur] && len(chain) < 12 {
		visited[cur] = true
		chain = append(chain, cur)
		info, ok := proxiesWrap.Proxies[cur]
		if !ok {
			break
		}
		lt := strings.ToLower(info.Type)
		if lt == "urltest" || lt == "fallback" || lt == "loadbalance" {
			dynGroups = append(dynGroups, fmt.Sprintf("%s(%s)", cur, info.Type))
		}
		if info.Now == "" {
			break
		}
		cur = info.Now
	}
	leaf := entryProxy
	if len(chain) > 0 {
		leaf = chain[len(chain)-1]
	}

	// Live /connections
	connRaw, _ := controllerRequest(ep, http.MethodGet, "/connections", nil)
	var connWrap struct {
		Connections []struct {
			ID          string   `json:"id"`
			Upload      int64    `json:"upload"`
			Download    int64    `json:"download"`
			Rule        string   `json:"rule"`
			RulePayload string   `json:"rulePayload"`
			Chains      []string `json:"chains"`
			Metadata    struct {
				Network string `json:"network"`
				Host    string `json:"host"`
				DstIP   string `json:"destinationIP"`
				DstPort string `json:"destinationPort"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	_ = json.Unmarshal(connRaw, &connWrap)

	var claudeConns, violations []ActiveConnection
	for _, c := range connWrap.Connections {
		h := c.Metadata.Host
		if h == "" {
			h = c.Metadata.DstIP
		}
		lh := strings.ToLower(h)
		if !(strings.Contains(lh, "anthropic.com") || strings.Contains(lh, "claude.ai") || strings.Contains(lh, "claude.com")) {
			continue
		}
		isDirect := false
		for _, ch := range c.Chains {
			if strings.EqualFold(ch, "DIRECT") {
				isDirect = true
			}
		}
		ac := ActiveConnection{
			ID: c.ID, Host: h, Port: c.Metadata.DstPort, Network: c.Metadata.Network,
			Rule: c.Rule, RulePayload: c.RulePayload, Chains: c.Chains,
			Upload: c.Upload, Download: c.Download, IsViolation: isDirect,
		}
		claudeConns = append(claudeConns, ac)
		if isDirect {
			violations = append(violations, ac)
		}
	}

	_, hasPin := proxiesWrap.Proxies["Claude-Pin"]
	return &ControllerSnapshot{
		ClientName:        ep.ClientName,
		BaseURL:           ep.BaseURL,
		KernelVersion:     verObj.Version,
		Mode:              cfgObj.Mode,
		TunEnabled:        cfgObj.Tun.Enable,
		MixedPort:         cfgObj.MixedPort,
		LeafNode:          leaf,
		RouteChain:        chain,
		MatchedRule:       matchedRule,
		IsDirect:          strings.EqualFold(leaf, "DIRECT"),
		HasDynamicGroup:   len(dynGroups) > 0,
		DynamicGroups:     dynGroups,
		HasClaudePin:      hasPin,
		ClaudeConnections: claudeConns,
		DirectViolations:  violations,
		TotalConnections:  len(connWrap.Connections),
	}, nil
}

func CloseConnection(ep ControllerEndpoint, id string) error {
	_, err := controllerRequest(ep, http.MethodDelete, "/connections/"+id, nil)
	return err
}

func GenerateOverrideJS(preferredNode, entryFn string) string {
	if entryFn == "" {
		entryFn = "main"
	}
	nodeJSON, _ := json.Marshal(preferredNode)
	return fmt.Sprintf(`// Claude Anti-Leak Global Extend Script (generated by Claude 环境体检 v1.2.0)
function %s(config) {
  const PREFERRED_NODE = %s;
  const rawNames = (config.proxies || []).map(p => p.name).filter(Boolean);
  const blockRe = /香港|港|HK|Hong\s*Kong|中国|内地|回国|澳门|澳門|MO|Macau|俄罗斯|俄|RU|Russia|伊朗|朝鲜|白俄|剩余流量|套餐到期|官网|自动|故障|直连|DIRECT|REJECT/i;
  let safeNodes = rawNames.filter(n => !blockRe.test(n));
  if (safeNodes.length === 0) safeNodes = rawNames.slice();
  if (PREFERRED_NODE && safeNodes.includes(PREFERRED_NODE)) {
    safeNodes = [PREFERRED_NODE, ...safeNodes.filter(n => n !== PREFERRED_NODE)];
  }
  config["proxy-groups"] = (config["proxy-groups"] || []).filter(g => g.name !== "Claude-Pin");
  config["proxy-groups"].unshift({
    name: "Claude-Pin",
    type: "select",
    proxies: safeNodes.length ? safeNodes : ["PROXY"]
  });

  const pinRules = [
    "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,anthropic.com)),REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,claude.ai)),REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,3478)),REJECT",
    "DOMAIN-SUFFIX,anthropic.com,Claude-Pin",
    "DOMAIN-SUFFIX,claude.ai,Claude-Pin",
    "DOMAIN-SUFFIX,claude.com,Claude-Pin",
    "DOMAIN-SUFFIX,clau.de,Claude-Pin",
    "DOMAIN-SUFFIX,akahelp.net,Claude-Pin",
    "DOMAIN-SUFFIX,l.google.com,Claude-Pin",
    "DOMAIN-SUFFIX,ipwho.is,Claude-Pin",
    "DOMAIN-SUFFIX,ipinfo.io,Claude-Pin",
    "DOMAIN-SUFFIX,ip.sb,Claude-Pin",
    "DOMAIN-SUFFIX,ipify.org,Claude-Pin",
    "DOMAIN,www.cloudflare.com,Claude-Pin"
  ];
  config.rules = [...pinRules, ...(config.rules || [])];

  const remoteDoh = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];
  const cnDoh = ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"];
  config.dns = Object.assign({}, config.dns || {}, {
    enable: true,
    ipv6: false,
    "respect-rules": true,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    nameserver: remoteDoh,
    "proxy-server-nameserver": cnDoh,
    "nameserver-policy": Object.assign({}, (config.dns && config.dns["nameserver-policy"]) || {}, {
      "geosite:cn": cnDoh,
      "+.anthropic.com": remoteDoh,
      "+.claude.ai": remoteDoh,
      "+.claude.com": remoteDoh,
      "+.akahelp.net": remoteDoh,
      "+.l.google.com": remoteDoh
    })
  });
  return config;
}
`, entryFn, string(nodeJSON))
}

func IsDefaultStubScript(txt string) bool {
	var clean []string
	for _, line := range strings.Split(txt, "\n") {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		if s := strings.TrimSpace(line); s != "" {
			clean = append(clean, s)
		}
	}
	joined := strings.Join(strings.Fields(strings.Join(clean, " ")), " ")
	return joined == "function main(config, profileName) { return config; }" ||
		joined == "function main(config) { return config; }" ||
		joined == "function main(config, profileName) { return config }" ||
		joined == "function main(config) { return config }"
}

func ComposeScript(preferredNode, customOrig string) string {
	if strings.TrimSpace(customOrig) == "" {
		return ManagedMarkerStart + "\n" + GenerateOverrideJS(preferredNode, "main") + ManagedMarkerEnd + "\n"
	}
	body := GenerateOverrideJS(preferredNode, "__claudeEnvGuardApply")
	return fmt.Sprintf(`%s
const __claudeOriginalUserMain = (function () {
%s
  return typeof main === "function" ? main : (c) => c;
})();

%s
function main(config, profileName) {
  const afterUser = __claudeOriginalUserMain(config, profileName) || config;
  return __claudeEnvGuardApply(afterUser, profileName);
}
%s
`, ManagedMarkerStart, customOrig, body, ManagedMarkerEnd)
}

func readBackup(path string) (*scriptBackup, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var b scriptBackup
	if err := json.Unmarshal(raw, &b); err != nil || b.Version != 1 || !strings.HasSuffix(b.TargetPath, ".js") {
		return nil, errors.New("备份文件损坏")
	}
	return &b, nil
}

func InstallScript(target ScriptTarget, preferredNode, stateDir string) (chained bool, err error) {
	if fi, e := os.Stat(target.ConfigDir); e != nil || !fi.IsDir() {
		return false, fmt.Errorf("未找到 %s 配置目录", target.DisplayName)
	}
	if err := os.MkdirAll(filepath.Dir(target.ScriptPath), 0o755); err != nil {
		return false, err
	}
	backupPath := filepath.Join(stateDir, target.BackupFileName)
	existingBackup, err := readBackup(backupPath)
	if err != nil {
		return false, err
	}

	var origForChain string
	if existingBackup != nil {
		rawOrig, _ := base64.StdEncoding.DecodeString(existingBackup.OriginalBase64)
		origForChain = string(rawOrig)
		chained = existingBackup.ChainedCustomScript
	} else {
		existingBytes, readErr := os.ReadFile(target.ScriptPath)
		hadFile := readErr == nil
		existingTxt := string(existingBytes)
		alreadyManaged := strings.Contains(existingTxt, ManagedMarkerStart)
		chained = !alreadyManaged && strings.TrimSpace(existingTxt) != "" && !IsDefaultStubScript(existingTxt)
		origForChain = existingTxt

		b := scriptBackup{
			Version: 1, TargetPath: target.ScriptPath, HadFile: hadFile,
			OriginalBase64: base64.StdEncoding.EncodeToString(existingBytes),
			ChainedCustomScript: chained, SavedAt: time.Now(),
		}
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return false, err
		}
		bBytes, _ := json.Marshal(b)
		if err := os.WriteFile(backupPath+".tmp", bBytes, 0o600); err != nil {
			return false, err
		}
		if err := os.Rename(backupPath+".tmp", backupPath); err != nil {
			return false, err
		}
	}

	var script string
	if chained {
		script = ComposeScript(preferredNode, origForChain)
	} else {
		script = ComposeScript(preferredNode, "")
	}
	if err := os.WriteFile(target.ScriptPath+".tmp", []byte(script), 0o644); err != nil {
		return false, err
	}
	return chained, os.Rename(target.ScriptPath+".tmp", target.ScriptPath)
}

func RestoreScript(target ScriptTarget, stateDir string) error {
	backupPath := filepath.Join(stateDir, target.BackupFileName)
	b, err := readBackup(backupPath)
	if err != nil {
		return err
	}
	if b == nil {
		return errors.New("未找到原始脚本备份")
	}
	orig, err := base64.StdEncoding.DecodeString(b.OriginalBase64)
	if err != nil {
		return errors.New("备份文件损坏")
	}
	if b.HadFile {
		if err := os.WriteFile(b.TargetPath+".tmp", orig, 0o644); err != nil {
			return err
		}
		if err := os.Rename(b.TargetPath+".tmp", b.TargetPath); err != nil {
			return err
		}
	} else if target.Standalone {
		_ = os.Remove(b.TargetPath)
	} else {
		stub := "// Define main function (script entry)\n\nfunction main(config, profileName) {\n  return config;\n}\n"
		_ = os.WriteFile(b.TargetPath, []byte(stub), 0o644)
	}
	_ = os.Remove(backupPath)
	return nil
}
