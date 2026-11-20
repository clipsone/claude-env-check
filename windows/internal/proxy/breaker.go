package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type UpstreamProtocol string

const (
	ProtoHTTP   UpstreamProtocol = "httpConnect"
	ProtoSOCKS5 UpstreamProtocol = "socks5"
)

type GateState struct {
	Open        bool   `json:"open"`
	ExitIP      string `json:"exitIP,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	TripReason  string `json:"tripReason,omitempty"`
}

type AuditEntry struct {
	ID             string    `json:"id"`
	StartedAt      time.Time `json:"startedAt"`
	EndedAt        time.Time `json:"endedAt"`
	Method         string    `json:"method"`
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	IsClaudeDomain bool      `json:"isClaudeDomain"`
	Decision       string    `json:"decision"` // allowed | blocked | rejectedLoopback | upstreamError
	Reason         string    `json:"reason,omitempty"`
	ExitIP         string    `json:"exitIP,omitempty"`
	ExitCountry    string    `json:"exitCountry,omitempty"`
	BytesUp        int64     `json:"bytesUp"`
	BytesDown      int64     `json:"bytesDown"`
	DurationMs     int64     `json:"durationMs"`
}

type AuditStats struct {
	Total          int `json:"total"`
	Allowed        int `json:"allowed"`
	Blocked        int `json:"blocked"`
	UpstreamErrors int `json:"upstreamErrors"`
}

type AuditLog struct {
	mu      sync.Mutex
	path    string
	entries []AuditEntry
}

func NewAuditLog(stateDir string) *AuditLog {
	al := &AuditLog{path: filepath.Join(stateDir, "connection-audit.json")}
	al.load()
	return al
}

func (a *AuditLog) load() {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return
	}
	var items []AuditEntry
	if json.Unmarshal(data, &items) == nil {
		a.entries = pruneAudit(items, time.Now())
	}
}

func pruneAudit(items []AuditEntry, now time.Time) []AuditEntry {
	cutoff := now.Add(-48 * time.Hour)
	out := make([]AuditEntry, 0, len(items))
	for _, it := range items {
		if it.StartedAt.After(cutoff) {
			out = append(out, it)
		}
	}
	if len(out) > 1000 {
		out = out[len(out)-1000:]
	}
	return out
}

func (a *AuditLog) Append(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = pruneAudit(append(a.entries, e), time.Now())
	_ = a.saveLocked()
}

func (a *AuditLog) Snapshot(limit int) (AuditStats, []AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = pruneAudit(a.entries, time.Now())
	var stats AuditStats
	stats.Total = len(a.entries)
	for _, e := range a.entries {
		switch e.Decision {
		case "allowed":
			stats.Allowed++
		case "blocked", "rejectedLoopback":
			stats.Blocked++
		case "upstreamError":
			stats.UpstreamErrors++
		}
	}
	if limit <= 0 || limit > len(a.entries) {
		limit = len(a.entries)
	}
	recent := make([]AuditEntry, 0, limit)
	for i := len(a.entries) - 1; i >= len(a.entries)-limit; i-- {
		recent = append(recent, a.entries[i])
	}
	return stats, recent
}

func (a *AuditLog) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = nil
	_ = os.Remove(a.path)
}

func (a *AuditLog) ExportCSV() string {
	_, recent := a.Snapshot(1000)
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"started_at", "method", "host", "port", "is_claude", "decision", "exit_ip", "exit_country", "bytes_up", "bytes_down", "duration_ms", "reason"})
	for _, e := range recent {
		_ = w.Write([]string{
			e.StartedAt.Format(time.RFC3339),
			e.Method,
			e.Host,
			strconv.Itoa(e.Port),
			strconv.FormatBool(e.IsClaudeDomain),
			e.Decision,
			e.ExitIP,
			e.ExitCountry,
			strconv.FormatInt(e.BytesUp, 10),
			strconv.FormatInt(e.BytesDown, 10),
			strconv.FormatInt(e.DurationMs, 10),
			e.Reason,
		})
	}
	w.Flush()
	return buf.String()
}

func (a *AuditLog) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(a.entries)
	if err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

func IsClaudeHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, suffix := range []string{"anthropic.com", "claude.ai", "claude.com", "clau.de"} {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	return false
}

func IsLoopbackOrLinkLocal(host string) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "0.0.0.0" || h == "::1" || h == "::" {
		return true
	}
	if strings.HasPrefix(h, "127.") || strings.HasPrefix(h, "169.254.") || strings.HasPrefix(h, "fe80:") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}

type tunnelPair struct {
	client   net.Conn
	upstream net.Conn
}

type CircuitBreaker struct {
	mu                sync.Mutex
	listener          net.Listener
	boundPort         int
	upstreamPort      int
	upstreamProto     UpstreamProtocol
	gate              GateState
	active            map[uint64]*tunnelPair
	nextID            uint64
	audit             *AuditLog
	onUpstreamFailure func(reason string)
}

func NewCircuitBreaker(audit *AuditLog, onUpstreamFailure func(string)) *CircuitBreaker {
	return &CircuitBreaker{
		upstreamProto:     ProtoHTTP,
		gate:              GateState{Open: false, TripReason: "尚未完成出口校验"},
		active:            make(map[uint64]*tunnelPair),
		audit:             audit,
		onUpstreamFailure: onUpstreamFailure,
	}
}

func (b *CircuitBreaker) ListeningPort() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.boundPort
}

func (b *CircuitBreaker) ActiveTunnels() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.active)
}

func (b *CircuitBreaker) Gate() GateState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gate
}

func (b *CircuitBreaker) SetGate(state GateState) {
	b.mu.Lock()
	b.gate = state
	var toKill []*tunnelPair
	if !state.Open && len(b.active) > 0 {
		for k, p := range b.active {
			toKill = append(toKill, p)
			delete(b.active, k)
		}
	}
	b.mu.Unlock()

	for _, p := range toKill {
		if p.client != nil {
			_ = p.client.Close()
		}
		if p.upstream != nil {
			_ = p.upstream.Close()
		}
	}
}

func (b *CircuitBreaker) Start(preferredPort, upstreamPort int, proto UpstreamProtocol, initial GateState) (int, error) {
	if upstreamPort < 1 || upstreamPort > 65535 {
		return 0, errors.New("上游代理端口无效")
	}
	b.Stop()

	candidates := make([]int, 0, 23)
	if preferredPort >= 1024 && preferredPort <= 65535 {
		candidates = append(candidates, preferredPort)
	}
	for p := 17899; p <= 17920; p++ {
		if p != preferredPort {
			candidates = append(candidates, p)
		}
	}

	var ln net.Listener
	var bound int
	var lastErr error
	for _, p := range candidates {
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln = l
			bound = p
			break
		}
		lastErr = err
	}
	if ln == nil {
		return 0, fmt.Errorf("本地守护端口 17899–17920 绑定失败: %w", lastErr)
	}

	b.mu.Lock()
	b.listener = ln
	b.boundPort = bound
	b.upstreamPort = upstreamPort
	b.upstreamProto = proto
	b.gate = initial
	b.mu.Unlock()

	go b.acceptLoop(ln)
	return bound, nil
}

func (b *CircuitBreaker) Stop() {
	b.mu.Lock()
	ln := b.listener
	b.listener = nil
	b.boundPort = 0
	var toKill []*tunnelPair
	for k, p := range b.active {
		toKill = append(toKill, p)
		delete(b.active, k)
	}
	b.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, p := range toKill {
		if p.client != nil {
			_ = p.client.Close()
		}
		if p.upstream != nil {
			_ = p.upstream.Close()
		}
	}
}

func (b *CircuitBreaker) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go b.handleClient(conn)
	}
}

func (b *CircuitBreaker) register(client, upstream net.Conn) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	id := b.nextID
	b.active[id] = &tunnelPair{client: client, upstream: upstream}
	return id
}

func (b *CircuitBreaker) unregister(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.active, id)
}

func (b *CircuitBreaker) handleClient(client net.Conn) {
	defer client.Close()
	startedAt := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReaderSize(client, 16*1024)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	// Fast local health endpoint for claude-safe (<5ms, zero upstream traffic)
	if (req.Method == http.MethodGet || req.Method == http.MethodHead) && req.URL.Path == "/__claude_guard_health" {
		b.writeHealthResponse(client)
		return
	}

	host, port := extractTargetHostPort(req)
	if host == "" {
		writeSimpleHTTP(client, "400 Bad Request", "text/plain; charset=utf-8", nil, "Malformed proxy request.\n")
		return
	}
	isClaude := IsClaudeHost(host)

	if IsLoopbackOrLinkLocal(host) {
		writeSimpleHTTP(client, "403 Forbidden", "text/plain; charset=utf-8", nil, "Loopback targets are forbidden.\n")
		b.recordAudit(AuditEntry{
			ID: fmt.Sprintf("%d", time.Now().UnixNano()), StartedAt: startedAt, EndedAt: time.Now(),
			Method: req.Method, Host: host, Port: port, IsClaudeDomain: isClaude,
			Decision: "rejectedLoopback", Reason: "拒绝代理访问本机回环地址", DurationMs: max(1, time.Since(startedAt).Milliseconds()),
		})
		return
	}

	b.mu.Lock()
	gate := b.gate
	upPort := b.upstreamPort
	upProto := b.upstreamProto
	b.mu.Unlock()

	if !gate.Open {
		writeSimpleHTTP(client, "503 Service Unavailable", "text/plain; charset=utf-8",
			map[string]string{"X-Claude-EnvCheck-Breaker": "tripped"},
			"Claude EnvCheck Circuit Breaker Tripped: "+gate.TripReason+"\n")
		b.recordAudit(AuditEntry{
			ID: fmt.Sprintf("%d", time.Now().UnixNano()), StartedAt: startedAt, EndedAt: time.Now(),
			Method: req.Method, Host: host, Port: port, IsClaudeDomain: isClaude,
			Decision: "blocked", Reason: gate.TripReason, DurationMs: max(1, time.Since(startedAt).Milliseconds()),
		})
		return
	}

	upstream, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", upPort), 5*time.Second)
	if err != nil {
		writeSimpleHTTP(client, "502 Bad Gateway", "text/plain; charset=utf-8", nil, "Unable to reach upstream proxy.\n")
		b.recordAudit(AuditEntry{
			ID: fmt.Sprintf("%d", time.Now().UnixNano()), StartedAt: startedAt, EndedAt: time.Now(),
			Method: req.Method, Host: host, Port: port, IsClaudeDomain: isClaude,
			Decision: "upstreamError", Reason: "无法连接上游代理: " + err.Error(), ExitIP: gate.ExitIP, ExitCountry: gate.CountryCode,
			DurationMs: max(1, time.Since(startedAt).Milliseconds()),
		})
		if b.onUpstreamFailure != nil {
			go b.onUpstreamFailure("无法连接上游代理")
		}
		return
	}
	defer upstream.Close()

	id := b.register(client, upstream)
	defer b.unregister(id)

	var upBytes, downBytes int64
	if req.Method == http.MethodConnect {
		if upProto == ProtoSOCKS5 {
			if err := socks5Connect(upstream, host, port); err != nil {
				writeSimpleHTTP(client, "502 Bad Gateway", "text/plain; charset=utf-8", nil, "SOCKS5 upstream error: "+err.Error()+"\n")
				b.recordAudit(AuditEntry{
					ID: fmt.Sprintf("%d", time.Now().UnixNano()), StartedAt: startedAt, EndedAt: time.Now(),
					Method: "CONNECT", Host: host, Port: port, IsClaudeDomain: isClaude,
					Decision: "upstreamError", Reason: "上游 SOCKS5 握手失败: " + err.Error(), ExitIP: gate.ExitIP, ExitCountry: gate.CountryCode,
					DurationMs: max(1, time.Since(startedAt).Milliseconds()),
				})
				if b.onUpstreamFailure != nil {
					go b.onUpstreamFailure("上游 SOCKS5 握手失败")
				}
				return
			}
		} else {
			if err := httpConnectHandshake(upstream, host, port); err != nil {
				writeSimpleHTTP(client, "502 Bad Gateway", "text/plain; charset=utf-8", nil, "HTTP upstream error: "+err.Error()+"\n")
				b.recordAudit(AuditEntry{
					ID: fmt.Sprintf("%d", time.Now().UnixNano()), StartedAt: startedAt, EndedAt: time.Now(),
					Method: "CONNECT", Host: host, Port: port, IsClaudeDomain: isClaude,
					Decision: "upstreamError", Reason: "上游 CONNECT 失败: " + err.Error(), ExitIP: gate.ExitIP, ExitCountry: gate.CountryCode,
					DurationMs: max(1, time.Since(startedAt).Milliseconds()),
				})
				if b.onUpstreamFailure != nil {
					go b.onUpstreamFailure("上游 CONNECT 失败")
				}
				return
			}
		}

		// Re-check breaker right before establishing tunnel
		if !b.Gate().Open {
			writeSimpleHTTP(client, "503 Service Unavailable", "text/plain; charset=utf-8", nil, "Breaker tripped during handshake.\n")
			return
		}
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		upBytes, downBytes = relayBidirectional(br, client, upstream)
	} else {
		if upProto == ProtoSOCKS5 {
			if err := socks5Connect(upstream, host, port); err != nil {
				writeSimpleHTTP(client, "502 Bad Gateway", "text/plain; charset=utf-8", nil, "SOCKS5 upstream error.\n")
				return
			}
			req.RequestURI = ""
			req.URL.Scheme = ""
			req.URL.Host = ""
			if err := req.Write(upstream); err != nil {
				return
			}
		} else {
			if err := req.WriteProxy(upstream); err != nil {
				return
			}
		}
		upBytes, downBytes = relayBidirectional(br, client, upstream)
	}

	b.recordAudit(AuditEntry{
		ID: fmt.Sprintf("%d", time.Now().UnixNano()), StartedAt: startedAt, EndedAt: time.Now(),
		Method: req.Method, Host: host, Port: port, IsClaudeDomain: isClaude,
		Decision: "allowed", ExitIP: gate.ExitIP, ExitCountry: gate.CountryCode,
		BytesUp: upBytes, BytesDown: downBytes, DurationMs: max(1, time.Since(startedAt).Milliseconds()),
	})
}

func (b *CircuitBreaker) writeHealthResponse(client net.Conn) {
	b.mu.Lock()
	gate := b.gate
	upPort := b.upstreamPort
	upProto := b.upstreamProto
	b.mu.Unlock()

	if gate.Open {
		payload, _ := json.Marshal(map[string]any{
			"state":            "open",
			"ip":               gate.ExitIP,
			"country":          gate.CountryCode,
			"upstreamPort":     upPort,
			"upstreamProtocol": string(upProto),
		})
		writeSimpleHTTP(client, "200 OK", "application/json; charset=utf-8",
			map[string]string{"X-Claude-EnvCheck-Breaker": "open"}, string(payload)+"\n")
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"state":            "tripped",
		"reason":           gate.TripReason,
		"upstreamPort":     upPort,
		"upstreamProtocol": string(upProto),
	})
	writeSimpleHTTP(client, "503 Service Unavailable", "application/json; charset=utf-8",
		map[string]string{"X-Claude-EnvCheck-Breaker": "tripped"}, string(payload)+"\n")
}

func (b *CircuitBreaker) recordAudit(e AuditEntry) {
	if b.audit != nil {
		b.audit.Append(e)
	}
}

func extractTargetHostPort(req *http.Request) (string, int) {
	target := req.Host
	if req.Method == http.MethodConnect && req.URL != nil && req.URL.Host != "" {
		target = req.URL.Host
	} else if req.URL != nil && req.URL.Host != "" {
		target = req.URL.Host
	}
	if h, pStr, err := net.SplitHostPort(target); err == nil {
		if p, err := strconv.Atoi(pStr); err == nil && p >= 1 && p <= 65535 {
			return h, p
		}
	}
	clean := strings.Trim(target, "[]")
	if clean == "" {
		return "", 0
	}
	if req.Method == http.MethodConnect || (req.URL != nil && strings.EqualFold(req.URL.Scheme, "https")) {
		return clean, 443
	}
	return clean, 80
}

func httpConnectHandshake(upstream net.Conn, host string, port int) error {
	_ = upstream.SetDeadline(time.Now().Add(6 * time.Second))
	defer upstream.SetDeadline(time.Time{})

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", addr, addr); err != nil {
		return err
	}
	br := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// BuildSOCKS5ConnectPacket constructs an RFC 1928 SOCKS5 CONNECT packet (IPv4 / IPv6 / Domain).
func BuildSOCKS5ConnectPacket(host string, port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	clean := strings.Trim(strings.TrimSpace(host), "[]")
	pkt := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(clean); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			pkt = append(pkt, 0x01)
			pkt = append(pkt, v4...)
		} else {
			pkt = append(pkt, 0x04)
			pkt = append(pkt, ip.To16()...)
		}
	} else {
		if len(clean) == 0 || len(clean) > 255 {
			return nil, errors.New("invalid domain length")
		}
		pkt = append(pkt, 0x03, byte(len(clean)))
		pkt = append(pkt, []byte(clean)...)
	}
	pkt = append(pkt, byte(port>>8), byte(port&0xFF))
	return pkt, nil
}

func socks5Connect(upstream net.Conn, host string, port int) error {
	_ = upstream.SetDeadline(time.Now().Add(6 * time.Second))
	defer upstream.SetDeadline(time.Time{})

	if _, err := upstream.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(upstream, greet); err != nil {
		return err
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		return fmt.Errorf("SOCKS5 auth rejected (0x%02X)", greet[1])
	}
	pkt, err := BuildSOCKS5ConnectPacket(host, port)
	if err != nil {
		return err
	}
	if _, err := upstream.Write(pkt); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(upstream, head); err != nil {
		return err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 REP=0x%02X", head[1])
	}
	var discard int
	switch head[3] {
	case 0x01:
		discard = 4 + 2
	case 0x04:
		discard = 16 + 2
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(upstream, lb); err != nil {
			return err
		}
		discard = int(lb[0]) + 2
	default:
		return fmt.Errorf("unknown ATYP 0x%02X", head[3])
	}
	if _, err := io.CopyN(io.Discard, upstream, int64(discard)); err != nil {
		return err
	}
	return nil
}

func relayBidirectional(clientReader *bufio.Reader, client, upstream net.Conn) (int64, int64) {
	var wg sync.WaitGroup
	var upBytes, downBytes int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, clientReader)
		upBytes = n
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, upstream)
		downBytes = n
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	return upBytes, downBytes
}

func writeSimpleHTTP(conn net.Conn, status, contentType string, extra map[string]string, body string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n", status, contentType, len(body))
	for k, v := range extra {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	_, _ = io.WriteString(conn, sb.String())
}

// MakeHTTPClient creates an HTTP client optionally routed through a local HTTP or SOCKS5 proxy port.
func MakeHTTPClient(proxyPort int, proto UpstreamProtocol, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
	}
	if proxyPort > 0 {
		if proto == ProtoSOCKS5 {
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				conn, err := d.DialContext(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", proxyPort))
				if err != nil {
					return nil, err
				}
				h, pStr, err := net.SplitHostPort(addr)
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				p, _ := strconv.Atoi(pStr)
				if err := socks5Connect(conn, h, p); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return conn, nil
			}
		} else {
			u, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
