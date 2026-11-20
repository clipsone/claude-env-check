package reputation

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Vote struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Category string `json:"category"` // blacklist | tor | residentialPBL | hostingOrProxy
	Outcome  string `json:"outcome"`  // clean | flagged | unavailable
	Detail   string `json:"detail"`
}

type Report struct {
	IP               string `json:"ip"`
	Votes            []Vote `json:"votes"`
	BlacklistChecked int    `json:"blacklistChecked"`
	BlacklistHits    int    `json:"blacklistHits"`
	IsTorExit        bool   `json:"isTorExit"`
	IsSpamhausSevere bool   `json:"isSpamhausSevere"`
	HostingSignals   int    `json:"hostingSignals"`
	Severity         string `json:"severity"` // ok | caution | danger | neutral
	Headline         string `json:"headline"`
	Detail           string `json:"detail"`
}

func ReverseIPv4(ip string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return "", false
	}
	nums := make([]string, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != p {
			return "", false
		}
		nums[3-i] = p
	}
	return strings.Join(nums, "."), true
}

func isSpamhausRefused(code string) bool {
	return code == "127.255.255.252" || code == "127.255.255.254" || code == "127.255.255.255"
}

func ClassifySpamhausZen(ips []string) Vote {
	if len(ips) == 0 {
		return Vote{ID: "spamhaus-zen", Source: "Spamhaus ZEN", Category: "blacklist", Outcome: "clean", Detail: "未命中"}
	}
	allRefused := true
	for _, ip := range ips {
		if !isSpamhausRefused(ip) {
			allRefused = false
			break
		}
	}
	if allRefused {
		return Vote{ID: "spamhaus-zen", Source: "Spamhaus ZEN", Category: "blacklist", Outcome: "unavailable", Detail: "公共 DNS 限流跳过"}
	}
	var severe []string
	hasPBL := false
	for _, code := range ips {
		if isSpamhausRefused(code) {
			continue
		}
		switch code {
		case "127.0.0.2":
			severe = append(severe, "SBL")
		case "127.0.0.3":
			severe = append(severe, "CSS")
		case "127.0.0.4":
			severe = append(severe, "XBL")
		case "127.0.0.9":
			severe = append(severe, "DROP")
		case "127.0.0.10", "127.0.0.11":
			hasPBL = true
		default:
			if strings.HasPrefix(code, "127.0.0.") {
				severe = append(severe, code)
			}
		}
	}
	if len(severe) > 0 {
		return Vote{ID: "spamhaus-zen", Source: "Spamhaus ZEN", Category: "blacklist", Outcome: "flagged", Detail: "命中 " + strings.Join(severe, "/") + " 滥用库"}
	}
	if hasPBL {
		return Vote{ID: "spamhaus-zen", Source: "Spamhaus ZEN", Category: "residentialPBL", Outcome: "clean", Detail: "PBL 动态家宽段（非黑名单）"}
	}
	return Vote{ID: "spamhaus-zen", Source: "Spamhaus ZEN", Category: "blacklist", Outcome: "clean", Detail: "未命中"}
}

func ClassifySpamhausDrop(ips []string) Vote {
	if len(ips) == 0 {
		return Vote{ID: "spamhaus-drop", Source: "Spamhaus DROP", Category: "blacklist", Outcome: "clean", Detail: "未命中"}
	}
	allRefused := true
	for _, ip := range ips {
		if !isSpamhausRefused(ip) {
			allRefused = false
			break
		}
	}
	if allRefused {
		return Vote{ID: "spamhaus-drop", Source: "Spamhaus DROP", Category: "blacklist", Outcome: "unavailable", Detail: "公共 DNS 限流跳过"}
	}
	for _, code := range ips {
		if strings.HasPrefix(code, "127.0.0.") {
			return Vote{ID: "spamhaus-drop", Source: "Spamhaus DROP", Category: "blacklist", Outcome: "flagged", Detail: "命中 DROP 高危网段"}
		}
	}
	return Vote{ID: "spamhaus-drop", Source: "Spamhaus DROP", Category: "blacklist", Outcome: "clean", Detail: "未命中"}
}

func ClassifyTorExit(ips []string) Vote {
	for _, ip := range ips {
		if ip == "127.0.0.2" {
			return Vote{ID: "tor-exit", Source: "Tor 出口库", Category: "tor", Outcome: "flagged", Detail: "确认为 Tor 匿名出口"}
		}
	}
	return Vote{ID: "tor-exit", Source: "Tor 出口库", Category: "tor", Outcome: "clean", Detail: "未命中"}
}

func ClassifyDroneBL(ips []string) Vote {
	var hits []string
	for _, ip := range ips {
		if strings.HasPrefix(ip, "127.0.0.") {
			hits = append(hits, ip)
		}
	}
	if len(hits) > 0 {
		return Vote{ID: "dronebl", Source: "DroneBL", Category: "blacklist", Outcome: "flagged", Detail: "命中开放代理/僵尸主机库 (" + strings.Join(hits, ",") + ")"}
	}
	return Vote{ID: "dronebl", Source: "DroneBL", Category: "blacklist", Outcome: "clean", Detail: "未命中"}
}

func ClassifyUCEProtect(ips []string) Vote {
	for _, ip := range ips {
		if ip == "127.0.0.2" {
			return Vote{ID: "uceprotect-l1", Source: "UCEPROTECT L1", Category: "blacklist", Outcome: "flagged", Detail: "命中单 IP 滥用记录"}
		}
	}
	return Vote{ID: "uceprotect-l1", Source: "UCEPROTECT L1", Category: "blacklist", Outcome: "clean", Detail: "未命中"}
}

func Synthesize(ip string, votes []Vote) Report {
	var checked []Vote
	var flagged []Vote
	var hosting []Vote
	isTor := false
	isSpamhausSevere := false
	pblNote := ""

	for _, v := range votes {
		if v.Category == "hostingOrProxy" {
			if v.Outcome == "flagged" {
				hosting = append(hosting, v)
			}
			continue
		}
		if v.Outcome == "unavailable" {
			continue
		}
		checked = append(checked, v)
		if v.Category == "residentialPBL" && v.Detail != "" {
			pblNote = " · " + v.Detail
		}
		if v.Outcome == "flagged" {
			flagged = append(flagged, v)
			if v.Category == "tor" {
				isTor = true
			}
			if v.ID == "spamhaus-zen" || v.ID == "spamhaus-drop" {
				isSpamhausSevere = true
			}
		}
	}

	flaggedNames := make([]string, 0, len(flagged))
	for _, f := range flagged {
		if f.Detail != "" {
			flaggedNames = append(flaggedNames, fmt.Sprintf("%s(%s)", f.Source, f.Detail))
		} else {
			flaggedNames = append(flaggedNames, f.Source)
		}
	}
	checkedNames := make([]string, 0, len(checked))
	for _, c := range checked {
		checkedNames = append(checkedNames, c.Source)
	}

	checkedCount := len(checked)
	rep := Report{
		IP:               ip,
		Votes:            votes,
		BlacklistChecked: checkedCount,
		BlacklistHits:    len(flagged),
		IsTorExit:        isTor,
		IsSpamhausSevere: isSpamhausSevere,
		HostingSignals:   len(hosting),
	}

	switch {
	case isTor:
		rep.Severity = "danger"
		rep.Headline = fmt.Sprintf("高危 · 命中 Tor 匿名出口（%d/%d）", len(flagged), checkedCount)
		rep.Detail = "命中来源：" + strings.Join(flaggedNames, "、") + "。Anthropic / Cloudflare 对 Tor 出口极易直接封禁，请立即更换节点。"
	case isSpamhausSevere || len(flagged) >= 2:
		rep.Severity = "danger"
		rep.Headline = fmt.Sprintf("高危 · 多源/权威黑名单命中（%d/%d）", len(flagged), checkedCount)
		rep.Detail = "命中来源：" + strings.Join(flaggedNames, "、") + "。建议更换更干净的独享/低滥用节点。"
	case len(flagged) == 1:
		rep.Severity = "caution"
		rep.Headline = fmt.Sprintf("单源轻微命中（1/%d）· 多数库干净", checkedCount)
		rep.Detail = fmt.Sprintf("仅 %s 命中，其余 %d 个权威库全绿（单源易误报，可继续观察或按需换节点）。", strings.Join(flaggedNames, "、"), max(0, checkedCount-1))
	case checkedCount == 0:
		rep.Severity = "neutral"
		rep.Headline = "黑名单探测受限"
		rep.Detail = "当前递归 DNS 拒绝了全部 DNSBL 查询，未产生负面判定。"
	case len(hosting) > 0:
		rep.Severity = "ok"
		rep.Headline = fmt.Sprintf("权威黑名单全绿（0/%d 命中）· 云/机房段", checkedCount)
		rep.Detail = fmt.Sprintf("已检 %d 个权威库全部干净（%s）；%s。", checkedCount, strings.Join(checkedNames, " / "), hosting[0].Detail)
	default:
		rep.Severity = "ok"
		rep.Headline = fmt.Sprintf("纯净 · 权威黑名单全绿（0/%d 命中）", checkedCount)
		rep.Detail = fmt.Sprintf("已检 %d 个权威黑名单与 Tor 库均未命中（%s）%s。", checkedCount, strings.Join(checkedNames, " / "), pblNote)
	}
	return rep
}

func lookupIPv4(ctx context.Context, domain string) []string {
	c, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(c, "ip4", domain)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

func Probe(ctx context.Context, ip string, isHosting bool, asnMeta string) *Report {
	rev, ok := ReverseIPv4(ip)
	if !ok {
		return nil
	}
	votes := make([]Vote, 5)
	var wg sync.WaitGroup
	queries := []struct {
		idx int
		dom string
		fn  func([]string) Vote
	}{
		{0, rev + ".zen.spamhaus.org", ClassifySpamhausZen},
		{1, rev + ".drop.spamhaus.org", ClassifySpamhausDrop},
		{2, rev + ".dnsel.torproject.org", ClassifyTorExit},
		{3, rev + ".dnsbl.dronebl.org", ClassifyDroneBL},
		{4, rev + ".dnsbl-1.uceprotect.net", ClassifyUCEProtect},
	}
	for _, q := range queries {
		wg.Add(1)
		go func(idx int, dom string, fn func([]string) Vote) {
			defer wg.Done()
			votes[idx] = fn(lookupIPv4(ctx, dom))
		}(q.idx, q.dom, q.fn)
	}
	wg.Wait()
	if isHosting {
		detail := "识别为云/机房段"
		if asnMeta != "" {
			detail = asnMeta + " 偏向云/机房段"
		}
		votes = append(votes, Vote{
			ID: "asn-hosting", Source: "ASN 机房段特征", Category: "hostingOrProxy", Outcome: "flagged", Detail: detail,
		})
	}
	rep := Synthesize(ip, votes)
	return &rep
}
