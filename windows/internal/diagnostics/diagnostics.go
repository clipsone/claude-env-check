package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/clipsone/claude-env-check/windows/internal/proxy"
	"github.com/clipsone/claude-env-check/windows/internal/regions"
	"github.com/clipsone/claude-env-check/windows/internal/reputation"
)

type Reading struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"` // egress | network | claude | local
	Value    string `json:"value"`
	Detail   string `json:"detail,omitempty"`
	Severity string `json:"severity"` // ok | caution | danger | neutral | pending
}

type RecommendedAction struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Guidance string `json:"guidance"`
}

type Verdict struct {
	Level        string              `json:"level"` // healthy | caution | risk | offlineOnly
	Headline     string              `json:"headline"`
	Summary      string              `json:"summary"`
	OKCount      int                 `json:"okCount"`
	CautionCount int                 `json:"cautionCount"`
	DangerCount  int                 `json:"dangerCount"`
	PendingCount int                 `json:"pendingCount"`
	Actions      []RecommendedAction `json:"actions"`
}

type Snapshot struct {
	CapturedAt          time.Time `json:"capturedAt"`
	Online              bool      `json:"online"`
	ProbeRoute          string    `json:"probeRoute"`
	ObservedExitIP      string    `json:"observedExitIP,omitempty"`
	ObservedExitCountry string    `json:"observedExitCountry,omitempty"`
	ObservedExitTZ      string    `json:"observedExitTZ,omitempty"`
	Readings            []Reading `json:"readings"`
	Verdict             Verdict   `json:"verdict"`
}

type GeoSource struct {
	Source      string `json:"source"`
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	RegionName  string `json:"regionName"`
	ASN         int    `json:"asn"`
	Org         string `json:"org"`
	TimeZone    string `json:"timeZone"`
	Colo        string `json:"colo"`
	Err         string `json:"err,omitempty"`
}

type MultiSourceGeo struct {
	Sources        []GeoSource `json:"sources"`
	PrimaryIP      string      `json:"primaryIP"`
	PrimaryCountry string      `json:"primaryCountry"`
	PrimaryCity    string      `json:"primaryCity"`
	PrimaryRegion  string      `json:"primaryRegion"`
	PrimaryTZ      string      `json:"primaryTZ"`
	ASN            int         `json:"asn"`
	Org            string      `json:"org"`
	Colo           string      `json:"colo"`
	NetworkKind    string      `json:"networkKind"` // residential | hosting | unknown
	Split          bool        `json:"split"`
	SplitCountries []string    `json:"splitCountries,omitempty"`
	AgreeCount     int         `json:"agreeCount"`
}

type ExitSample struct {
	CapturedAt  time.Time `json:"capturedAt"`
	IP          string    `json:"ip"`
	CountryCode string    `json:"countryCode"`
	ASN         int       `json:"asn,omitempty"`
	Org         string    `json:"org,omitempty"`
	NetworkKind string    `json:"networkKind"`
	ProbePath   string    `json:"probePath"`
}

type ExitDriftSummary struct {
	SampleCount           int          `json:"sampleCount"`
	UniqueIPCount         int          `json:"uniqueIPCount"`
	IPChanges             int          `json:"ipChanges"`
	CountryChanges        int          `json:"countryChanges"`
	GuardedCountryChanges int          `json:"guardedCountryChanges"`
	Countries             []string     `json:"countries"`
	RecentSamples         []ExitSample `json:"recentSamples"`
}

type ExitHistoryStore struct {
	mu      sync.Mutex
	path    string
	samples []ExitSample
}

func NewExitHistoryStore(stateDir string) *ExitHistoryStore {
	s := &ExitHistoryStore{path: filepath.Join(stateDir, "exit-history.json")}
	s.load()
	return s
}

func (h *ExitHistoryStore) load() {
	raw, err := os.ReadFile(h.path)
	if err != nil {
		return
	}
	var items []ExitSample
	if json.Unmarshal(raw, &items) == nil {
		h.samples = pruneSamples(items, time.Now())
	}
}

func pruneSamples(items []ExitSample, now time.Time) []ExitSample {
	cutoff := now.Add(-48 * time.Hour)
	out := make([]ExitSample, 0, len(items))
	for _, s := range items {
		if s.CapturedAt.After(cutoff) {
			out = append(out, s)
		}
	}
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}

func (h *ExitHistoryStore) Record(sample ExitSample) ExitDriftSummary {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = pruneSamples(append(h.samples, sample), time.Now())
	_ = h.saveLocked()
	return summarizeSamples(h.samples)
}

func (h *ExitHistoryStore) Summary() ExitDriftSummary {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = pruneSamples(h.samples, time.Now())
	return summarizeSamples(h.samples)
}

func (h *ExitHistoryStore) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = nil
	_ = os.Remove(h.path)
}

func (h *ExitHistoryStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(h.samples)
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}

func summarizeSamples(samples []ExitSample) ExitDriftSummary {
	if len(samples) == 0 {
		return ExitDriftSummary{}
	}
	ips := map[string]bool{}
	var countries []string
	var lastIP, lastCC, lastGuardedCC string
	ipChanges, ccChanges, guardedChanges := 0, 0, 0
	for _, s := range samples {
		ips[s.IP] = true
		if lastIP != "" && lastIP != s.IP {
			ipChanges++
		}
		lastIP = s.IP
		if s.CountryCode != "" {
			if len(countries) == 0 || countries[len(countries)-1] != s.CountryCode {
				countries = append(countries, s.CountryCode)
			}
			if lastCC != "" && lastCC != s.CountryCode {
				ccChanges++
			}
			lastCC = s.CountryCode
			if strings.Contains(s.ProbePath, "保护代理") || strings.Contains(s.ProbePath, "熔断守卫") {
				if lastGuardedCC != "" && lastGuardedCC != s.CountryCode {
					guardedChanges++
				}
				lastGuardedCC = s.CountryCode
			}
		}
	}
	recent := make([]ExitSample, 0, len(samples))
	for i := len(samples) - 1; i >= 0; i-- {
		recent = append(recent, samples[i])
	}
	return ExitDriftSummary{
		SampleCount:           len(samples),
		UniqueIPCount:         len(ips),
		IPChanges:             ipChanges,
		CountryChanges:        ccChanges,
		GuardedCountryChanges: guardedChanges,
		Countries:             countries,
		RecentSamples:         recent,
	}
}

// Unified ASN/org residential vs hosting classifier (matching macOS ExitClassifier)
var hostingASNs = map[int]bool{
	16509: true, 14618: true, 15169: true, 396982: true, 8075: true, 13335: true,
	14061: true, 20473: true, 63949: true, 24940: true, 16276: true, 45102: true,
	37963: true, 132203: true, 45090: true, 31898: true, 36352: true, 9009: true,
	212238: true, 60068: true,
}

func ClassifyNetwork(asn int, org string) string {
	lower := strings.ToLower(org)
	if asn == 16591 || strings.Contains(lower, "google fiber") {
		return "residential"
	}
	if hostingASNs[asn] {
		return "hosting"
	}
	for _, kw := range []string{"amazon", "aws", "digitalocean", "vultr", "linode", "hetzner", "ovh", "oracle", "alibaba", "tencent", "cloudflare", "datacenter", "hosting", "colocrossing", "m247", "datapacket"} {
		if strings.Contains(lower, kw) {
			return "hosting"
		}
	}
	for _, kw := range []string{"comcast", "verizon", "at&t", "charter", "spectrum", "cox", "ntt", "kddi", "softbank", "singtel", "starhub", "chunghwa", "bt ", "deutsche telekom", "orange", "fiber", "broadband", "telecom"} {
		if strings.Contains(lower, kw) {
			return "residential"
		}
	}
	return "unknown"
}

func IsFakeIP(ipStr string) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	return ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}

func ProbeMultiSourceGeo(proxyPort int, proto proxy.UpstreamProtocol) MultiSourceGeo {
	client := proxy.MakeHTTPClient(proxyPort, proto, 6*time.Second)
	sources := make([]GeoSource, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); sources[0] = fetchIPWho(client) }()
	go func() { defer wg.Done(); sources[1] = fetchIPInfoOrSB(client) }()
	go func() { defer wg.Done(); sources[2] = fetchCFTrace(client) }()
	wg.Wait()

	var usable []GeoSource
	for _, s := range sources {
		if s.IP != "" && s.CountryCode != "" {
			usable = append(usable, s)
		}
	}
	rep := MultiSourceGeo{Sources: sources, NetworkKind: "unknown"}
	if len(usable) == 0 {
		return rep
	}
	primary := usable[0]
	for _, s := range usable {
		if s.Source != "Cloudflare Trace" {
			primary = s
			break
		}
	}
	rep.PrimaryIP = primary.IP
	rep.PrimaryCountry = primary.CountryCode
	rep.PrimaryCity = primary.City
	rep.PrimaryRegion = primary.RegionName
	rep.PrimaryTZ = primary.TimeZone
	rep.ASN = primary.ASN
	rep.Org = primary.Org
	for _, s := range usable {
		if s.Colo != "" {
			rep.Colo = s.Colo
		}
		if rep.ASN == 0 && s.ASN != 0 {
			rep.ASN = s.ASN
		}
		if rep.Org == "" && s.Org != "" {
			rep.Org = s.Org
		}
		if rep.PrimaryTZ == "" && s.TimeZone != "" {
			rep.PrimaryTZ = s.TimeZone
		}
	}
	rep.NetworkKind = ClassifyNetwork(rep.ASN, rep.Org)

	ccSet := map[string]bool{}
	for _, s := range usable {
		ccSet[s.CountryCode] = true
	}
	if len(ccSet) > 1 {
		rep.Split = true
		for c := range ccSet {
			rep.SplitCountries = append(rep.SplitCountries, c)
		}
		sort.Strings(rep.SplitCountries)
	} else {
		rep.AgreeCount = len(usable)
	}
	return rep
}

func fetchCFTrace(c *http.Client) GeoSource {
	res := GeoSource{Source: "Cloudflare Trace"}
	resp, err := c.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			switch strings.TrimSpace(k) {
			case "ip":
				res.IP = strings.TrimSpace(v)
			case "loc":
				res.CountryCode = regions.Normalize(v)
			case "colo":
				res.Colo = strings.TrimSpace(v)
			}
		}
	}
	return res
}

func fetchIPWho(c *http.Client) GeoSource {
	res := GeoSource{Source: "ipwho.is"}
	resp, err := c.Get("https://ipwho.is/")
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()
	var obj struct {
		Success     bool   `json:"success"`
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
		Timezone struct {
			ID string `json:"id"`
		} `json:"timezone"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil || !obj.Success {
		res.Err = "解析失败"
		return res
	}
	res.IP = obj.IP
	res.CountryCode = regions.Normalize(obj.CountryCode)
	res.RegionName = obj.Region
	res.City = obj.City
	res.ASN = obj.Connection.ASN
	res.Org = obj.Connection.Org
	if res.Org == "" {
		res.Org = obj.Connection.ISP
	}
	res.TimeZone = obj.Timezone.ID
	return res
}

func fetchIPInfoOrSB(c *http.Client) GeoSource {
	res := GeoSource{Source: "ipinfo.io"}
	resp, err := c.Get("https://ipinfo.io/json")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var obj struct {
			IP       string `json:"ip"`
			Country  string `json:"country"`
			Region   string `json:"region"`
			City     string `json:"city"`
			Org      string `json:"org"`
			Timezone string `json:"timezone"`
		}
		if json.NewDecoder(resp.Body).Decode(&obj) == nil && obj.IP != "" && obj.Country != "" {
			res.IP = obj.IP
			res.CountryCode = regions.Normalize(obj.Country)
			res.RegionName = obj.Region
			res.City = obj.City
			res.TimeZone = obj.Timezone
			if strings.HasPrefix(obj.Org, "AS") {
				if sp := strings.IndexByte(obj.Org, ' '); sp > 2 {
					res.ASN, _ = strconv.Atoi(obj.Org[2:sp])
					res.Org = strings.TrimSpace(obj.Org[sp+1:])
				}
			} else {
				res.Org = obj.Org
			}
			return res
		}
	}
	res.Source = "api.ip.sb"
	req, _ := http.NewRequest(http.MethodGet, "https://api.ip.sb/geoip", nil)
	req.Header.Set("User-Agent", "ClaudeEnvironmentCheck/1.2")
	resp2, err := c.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp2.Body.Close()
	var sb struct {
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		ASN         int    `json:"asn"`
		ASNOrg      string `json:"asn_organization"`
		Timezone    string `json:"timezone"`
	}
	if json.NewDecoder(resp2.Body).Decode(&sb) == nil {
		res.IP = sb.IP
		res.CountryCode = regions.Normalize(sb.CountryCode)
		res.RegionName = sb.Region
		res.City = sb.City
		res.ASN = sb.ASN
		res.Org = sb.ASNOrg
		res.TimeZone = sb.Timezone
	}
	return res
}

func ProbeClaudeAPI(proxyPort int, proto proxy.UpstreamProtocol) (int, int64, error) {
	c := proxy.MakeHTTPClient(proxyPort, proto, 6*time.Second)
	req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/models", nil)
	req.Header.Set("anthropic-version", "2023-06-01")
	t0 := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, max(1, time.Since(t0).Milliseconds()), nil
}

// ClaudeSettingsManager handles safe atomic backup & restore of ~/.claude/settings.json on Windows/Unix.
type SettingsBackup struct {
	Version          int               `json:"version"`
	Mode             string            `json:"mode"`
	GuardPort        int               `json:"guardPort"`
	UpstreamPort     int               `json:"upstreamPort"`
	HadSettingsFile  bool              `json:"hadSettingsFile"`
	OriginalEnv      map[string]any    `json:"originalEnv"`
	AppliedEnv       map[string]string `json:"appliedEnv"`
	SavedAt          time.Time         `json:"savedAt"`
}

func ClaudeSettingsPath(home string) string {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".claude", "settings.json")
}

func ApplyGuardSettings(home, stateDir string, guardPort, upstreamPort int, extraEnv map[string]string) error {
	settingsPath := ClaudeSettingsPath(home)
	backupPath := filepath.Join(stateDir, "claude-settings-backup.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}

	root := map[string]any{}
	raw, err := os.ReadFile(settingsPath)
	hadFile := err == nil
	if hadFile && len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("settings.json 格式无效，已中止修改: %w", err)
		}
	}
	envMap, _ := root["env"].(map[string]any)
	if envMap == nil {
		envMap = map[string]any{}
	}

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", guardPort)
	applied := map[string]string{
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
	}
	for k, v := range extraEnv {
		applied[k] = v
	}

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		origEnv := map[string]any{}
		for k := range applied {
			if val, exists := envMap[k]; exists {
				origEnv[k] = val
			}
		}
		b := SettingsBackup{
			Version: 3, Mode: "guardProxy", GuardPort: guardPort, UpstreamPort: upstreamPort,
			HadSettingsFile: hadFile, OriginalEnv: origEnv, AppliedEnv: applied, SavedAt: time.Now(),
		}
		bBytes, _ := json.MarshalIndent(b, "", "  ")
		if err := os.WriteFile(backupPath+".tmp", bBytes, 0o600); err != nil {
			return err
		}
		if err := os.Rename(backupPath+".tmp", backupPath); err != nil {
			return err
		}
	}

	for k, v := range applied {
		envMap[k] = v
	}
	root["env"] = envMap
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(settingsPath+".tmp", append(out, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(settingsPath+".tmp", settingsPath)
}

func RestoreGuardSettings(home, stateDir string) error {
	backupPath := filepath.Join(stateDir, "claude-settings-backup.json")
	rawBackup, err := os.ReadFile(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var b SettingsBackup
	if err := json.Unmarshal(rawBackup, &b); err != nil {
		return errors.New("备份文件损坏")
	}
	settingsPath := ClaudeSettingsPath(home)
	raw, err := os.ReadFile(settingsPath)
	if err == nil {
		root := map[string]any{}
		if json.Unmarshal(raw, &root) == nil {
			if envMap, ok := root["env"].(map[string]any); ok {
				for k, appliedVal := range b.AppliedEnv {
					if cur, ok := envMap[k].(string); ok && cur == appliedVal {
						if orig, existed := b.OriginalEnv[k]; existed {
							envMap[k] = orig
						} else {
							delete(envMap, k)
						}
					}
				}
				if len(envMap) == 0 {
					delete(root, "env")
				} else {
					root["env"] = envMap
				}
			}
			if !b.HadSettingsFile && len(root) == 0 {
				_ = os.Remove(settingsPath)
			} else {
				out, _ := json.MarshalIndent(root, "", "  ")
				_ = os.WriteFile(settingsPath+".tmp", append(out, '\n'), 0o600)
				_ = os.Rename(settingsPath+".tmp", settingsPath)
			}
		}
	}
	_ = os.Remove(backupPath)
	return nil
}

func ReadConfiguredProcessEnv(home string) (proxyVal, processTZ string) {
	raw, err := os.ReadFile(ClaudeSettingsPath(home))
	if err != nil {
		return "", ""
	}
	var root struct {
		Env map[string]string `json:"env"`
	}
	if json.Unmarshal(raw, &root) != nil {
		return "", ""
	}
	proxyVal = root.Env["HTTPS_PROXY"]
	if proxyVal == "" {
		proxyVal = root.Env["HTTP_PROXY"]
	}
	processTZ = root.Env["TZ"]
	return proxyVal, processTZ
}

func Capture(ctx context.Context, online bool, proxyPort int, proto proxy.UpstreamProtocol, routeLabel string, history *ExitHistoryStore, home string) Snapshot {
	now := time.Now()
	if routeLabel == "" {
		if proxyPort > 0 {
			routeLabel = fmt.Sprintf("保护代理 127.0.0.1:%d", proxyPort)
		} else {
			routeLabel = "系统网络路径"
		}
	}

	var geo MultiSourceGeo
	var apiCode int
	var apiMs int64
	var apiErr error
	var rep *reputation.Report
	var dnsResIP, ecsSub string
	var fakeIP string

	if online {
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); geo = ProbeMultiSourceGeo(proxyPort, proto) }()
		go func() { defer wg.Done(); apiCode, apiMs, apiErr = ProbeClaudeAPI(proxyPort, proto) }()
		go func() {
			defer wg.Done()
			txts, err := net.DefaultResolver.LookupTXT(ctx, "whoami.ds.akahelp.net")
			if err == nil {
				for _, t := range txts {
					fields := strings.Fields(strings.ReplaceAll(t, "\"", " "))
					for i := 0; i+1 < len(fields); i++ {
						switch fields[i] {
						case "ns":
							dnsResIP = fields[i+1]
						case "ecs":
							ecsSub = fields[i+1]
						}
					}
				}
			}
		}()
		go func() {
			defer wg.Done()
			sub := fmt.Sprintf("envcheck-%d.claude.ai", now.UnixNano()%100000)
			if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", sub); err == nil && len(ips) > 0 {
				fakeIP = ips[0].String()
			}
		}()
		wg.Wait()

		if geo.PrimaryIP != "" {
			asnMeta := ""
			if geo.ASN > 0 {
				asnMeta = fmt.Sprintf("AS%d %s", geo.ASN, geo.Org)
			}
			rep = reputation.Probe(ctx, geo.PrimaryIP, geo.NetworkKind == "hosting", strings.TrimSpace(asnMeta))
		}
	}

	var drift ExitDriftSummary
	if online && geo.PrimaryIP != "" && history != nil {
		drift = history.Record(ExitSample{
			CapturedAt: now, IP: geo.PrimaryIP, CountryCode: geo.PrimaryCountry,
			ASN: geo.ASN, Org: geo.Org, NetworkKind: geo.NetworkKind, ProbePath: routeLabel,
		})
	} else if history != nil {
		drift = history.Summary()
	}

	cfgProxy, processTZ := ReadConfiguredProcessEnv(home)
	_, claudePathErr := exec.LookPath("claude")

	var readings []Reading
	// 1. Egress Region
	if !online {
		readings = append(readings, Reading{ID: "egress", Title: "公网出口与地区合规", Category: "egress", Value: "待联网检测", Severity: "pending"})
	} else if geo.PrimaryIP == "" {
		readings = append(readings, Reading{ID: "egress", Title: "公网出口与地区合规", Category: "egress", Value: "未能获取公网出口 IP", Detail: "3 家 GeoIP 源均失败", Severity: "danger"})
	} else {
		sup := regions.Support(geo.PrimaryCountry)
		sev := "ok"
		det := fmt.Sprintf("%s %s · 位于 Anthropic 官方 185 国支持清单", geo.PrimaryRegion, geo.PrimaryCity)
		if sup == regions.Unsupported {
			sev = "danger"
			det = "当前地区不在 Anthropic 官方支持清单内，请立即切换节点"
		} else if sup == regions.Unknown {
			sev = "caution"
		}
		readings = append(readings, Reading{
			ID: "egress", Title: "公网出口与地区合规", Category: "egress",
			Value: fmt.Sprintf("%s · %s", geo.PrimaryIP, regions.DisplayName(geo.PrimaryCountry)),
			Detail: strings.TrimSpace(det), Severity: sev,
		})
	}

	// 2. Claude API
	if !online {
		readings = append(readings, Reading{ID: "api", Title: "Claude API", Category: "egress", Value: "待联网检测", Severity: "pending"})
	} else if apiErr != nil {
		readings = append(readings, Reading{ID: "api", Title: "Claude API", Category: "egress", Value: "连接失败", Detail: apiErr.Error(), Severity: "danger"})
	} else {
		sev := "ok"
		det := "端点可达（401 为无密钥鉴权预期响应）"
		if apiCode == 403 {
			sev = "danger"
			det = "出口 IP 或地区被拒绝"
		} else if apiCode >= 500 || apiCode == 429 {
			sev = "caution"
			det = "上游限流或临时异常"
		}
		readings = append(readings, Reading{ID: "api", Title: "Claude API", Category: "egress", Value: fmt.Sprintf("HTTP %d · %d ms", apiCode, apiMs), Detail: det, Severity: sev})
	}

	// 3. Multi-source Geo Consensus
	if !online {
		readings = append(readings, Reading{ID: "consensus", Title: "多源 GeoIP 交叉核验", Category: "egress", Value: "待联网检测", Severity: "pending"})
	} else if geo.Split {
		readings = append(readings, Reading{ID: "consensus", Title: "多源 GeoIP 交叉核验", Category: "egress", Value: "分流冲突 · " + strings.Join(geo.SplitCountries, " ≠ "), Detail: "不同站点看到不同国家，请检查分流规则", Severity: "danger"})
	} else if geo.AgreeCount > 0 {
		readings = append(readings, Reading{ID: "consensus", Title: "多源 GeoIP 交叉核验", Category: "egress", Value: fmt.Sprintf("%d 源一致 · %s", geo.AgreeCount, geo.PrimaryCountry), Detail: "多源归属地完全一致", Severity: "ok"})
	} else {
		readings = append(readings, Reading{ID: "consensus", Title: "多源 GeoIP 交叉核验", Category: "egress", Value: "不可用", Severity: "neutral"})
	}

	// 4. IP Reputation (Multi-Source Blacklist Voting)
	if !online {
		readings = append(readings, Reading{ID: "reputation", Title: "IP 纯净度与黑名单", Category: "egress", Value: "待联网检测", Severity: "pending"})
	} else if rep != nil {
		readings = append(readings, Reading{ID: "reputation", Title: "IP 纯净度与黑名单", Category: "egress", Value: rep.Headline, Detail: rep.Detail, Severity: rep.Severity})
	} else {
		readings = append(readings, Reading{ID: "reputation", Title: "IP 纯净度与黑名单", Category: "egress", Value: "无 IPv4 出口可检", Severity: "neutral"})
	}

	// 5. 48h Exit Drift
	if drift.SampleCount == 0 {
		readings = append(readings, Reading{ID: "drift", Title: "48h 出口稳定性", Category: "egress", Value: "暂无记录", Severity: "pending"})
	} else if drift.CountryChanges >= 2 || drift.GuardedCountryChanges > 0 {
		readings = append(readings, Reading{ID: "drift", Title: "48h 出口稳定性", Category: "egress", Value: fmt.Sprintf("跨国跳变 %d 次 · %d 个 IP", drift.CountryChanges, drift.UniqueIPCount), Detail: "涉及地区：" + strings.Join(drift.Countries, " → "), Severity: "danger"})
	} else if drift.CountryChanges == 1 {
		readings = append(readings, Reading{ID: "drift", Title: "48h 出口稳定性", Category: "egress", Value: fmt.Sprintf("历史 1 次跨国切换 · %d 个 IP", drift.UniqueIPCount), Detail: "涉及地区：" + strings.Join(drift.Countries, " → ") + "（若是开代理前旧记录，清空历史即可）", Severity: "caution"})
	} else {
		readings = append(readings, Reading{ID: "drift", Title: "48h 出口稳定性", Category: "egress", Value: "出口稳定 · 无漂移", Detail: fmt.Sprintf("48h 采样 %d 次始终保持单一地区", drift.SampleCount), Severity: "ok"})
	}

	// 6. DNS & TUN
	if !online {
		readings = append(readings, Reading{ID: "dns", Title: "真实 DNS 递归出口", Category: "network", Value: "待联网检测", Severity: "pending"})
		readings = append(readings, Reading{ID: "tun", Title: "TUN / Fake-IP 接管", Category: "network", Value: "待联网检测", Severity: "pending"})
	} else {
		if dnsResIP != "" {
			det := "探测源 whoami.ds.akahelp.net"
			if ecsSub != "" {
				det += " · ECS " + ecsSub
			}
			readings = append(readings, Reading{ID: "dns", Title: "真实 DNS 递归出口", Category: "network", Value: dnsResIP, Detail: det, Severity: "ok"})
		} else {
			readings = append(readings, Reading{ID: "dns", Title: "真实 DNS 递归出口", Category: "network", Value: "未返回 TXT 记录", Severity: "caution"})
		}
		if IsFakeIP(fakeIP) {
			readings = append(readings, Reading{ID: "tun", Title: "TUN / Fake-IP 接管", Category: "network", Value: "已接管 · Fake-IP " + fakeIP, Detail: "命中 198.18.0.0/15，系统级 TUN 生效中", Severity: "ok"})
		} else {
			readings = append(readings, Reading{ID: "tun", Title: "TUN / Fake-IP 接管", Category: "network", Value: "未检测到 Fake-IP", Detail: "常规系统代理或仅代理 Claude Code 模式下属正常", Severity: "neutral"})
		}
	}

	// 7. Claude Code & Local Environment
	cliVal := "已安装（PATH 可用）"
	cliSev := "ok"
	if claudePathErr != nil {
		cliVal = "未在 PATH 中检测到 claude"
		cliSev = "neutral"
	}
	readings = append(readings, Reading{ID: "cli", Title: "Claude Code CLI", Category: "claude", Value: cliVal, Severity: cliSev})

	cfgVal := "未配置代理（使用系统网络）"
	cfgSev := "neutral"
	if cfgProxy != "" {
		cfgVal = cfgProxy
		cfgSev = "ok"
	}
	readings = append(readings, Reading{ID: "cfg", Title: "Claude Code 代理配置", Category: "claude", Value: cfgVal, Detail: ClaudeSettingsPath(home), Severity: cfgSev})

	tzName, tzOff := now.Zone()
	tzVal := fmt.Sprintf("%s (UTC%+d)", tzName, tzOff/3600)
	tzSev := "neutral"
	tzDet := "联网检测后自动与出口时区比对"
	if processTZ != "" {
		tzVal += " · 进程 TZ=" + processTZ
		tzSev = "ok"
		tzDet = "Claude Code 已启用进程级 TZ 对齐，未改动系统全局时区"
	} else if online && geo.PrimaryTZ != "" {
		if loc, err := time.LoadLocation(geo.PrimaryTZ); err == nil {
			_, exitOff := now.In(loc).Zone()
			if exitOff == tzOff {
				tzSev = "ok"
				tzDet = "UTC 偏移与出口 " + geo.PrimaryTZ + " 一致"
			} else {
				tzSev = "caution"
				tzDet = fmt.Sprintf("与出口 %s 存在时差（开启守卫并勾选进程级 TZ 对齐即可无侵入解决）", geo.PrimaryTZ)
			}
		}
	}
	readings = append(readings, Reading{ID: "tz", Title: "时区对齐", Category: "local", Value: tzVal, Detail: tzDet, Severity: tzSev})
	readings = append(readings, Reading{ID: "os", Title: "运行平台", Category: "local", Value: fmt.Sprintf("%s / %s", runtime.GOOS, runtime.GOARCH), Severity: "neutral"})

	verdict := buildVerdict(online, routeLabel, readings)
	return Snapshot{
		CapturedAt:          now,
		Online:              online,
		ProbeRoute:          routeLabel,
		ObservedExitIP:      geo.PrimaryIP,
		ObservedExitCountry: geo.PrimaryCountry,
		ObservedExitTZ:      geo.PrimaryTZ,
		Readings:            readings,
		Verdict:             verdict,
	}
}

func buildVerdict(online bool, routeLabel string, readings []Reading) Verdict {
	v := Verdict{}
	for _, r := range readings {
		switch r.Severity {
		case "ok":
			v.OKCount++
		case "caution":
			v.CautionCount++
		case "danger":
			v.DangerCount++
			v.Actions = append(v.Actions, RecommendedAction{ID: r.ID, Severity: "danger", Title: r.Title + " 异常", Guidance: r.Detail})
		case "pending":
			v.PendingCount++
		}
	}
	for _, r := range readings {
		if r.Severity == "caution" {
			v.Actions = append(v.Actions, RecommendedAction{ID: r.ID, Severity: "caution", Title: r.Title + "（按需关注）", Guidance: r.Detail})
		}
	}
	switch {
	case !online:
		v.Level = "offlineOnly"
		v.Headline = "已完成本机与配置体检（待执行联网检测）"
	case v.DangerCount > 0:
		v.Level = "risk"
		v.Headline = fmt.Sprintf("发现 %d 项高风险问题，暂不建议直接登录 Claude", v.DangerCount)
	case v.CautionCount > 0:
		v.Level = "caution"
		v.Headline = fmt.Sprintf("出口核心合规，但有 %d 项建议关注", v.CautionCount)
	default:
		v.Level = "healthy"
		v.Headline = "环境检测通过，可安心使用 Claude"
	}
	v.Summary = fmt.Sprintf("通过 %d 项 · 高危 %d 项 · 注意 %d 项（路径：%s）", v.OKCount, v.DangerCount, v.CautionCount, routeLabel)
	return v
}
