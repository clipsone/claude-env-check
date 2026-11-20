import Darwin
import Foundation
import Network

enum UpstreamProxyProtocol: String, Codable, Sendable {
    case httpConnect
    case socks5

    var shortLabel: String {
        switch self {
        case .httpConnect: "HTTP"
        case .socks5: "SOCKS5"
        }
    }
}

enum BreakerGateState: Equatable, Sendable {
    case open(exitIP: String?, countryCode: String?)
    case tripped(reason: String)

    var isOpen: Bool {
        if case .open = self { return true }
        return false
    }
}

enum CircuitBreakerError: LocalizedError {
    case invalidUpstreamPort
    case noAvailablePort
    case listenerFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidUpstreamPort: "上游代理端口无效。"
        case .noAvailablePort: "本地守护端口 17899–17920 均被占用，无法启动熔断转发器。"
        case .listenerFailed(let detail): "启动本地熔断转发器失败：\(detail)"
        }
    }
}

/// Zero-root, zero-MITM local HTTP/CONNECT circuit-breaker proxy.
/// Listens strictly on 127.0.0.1 and chains outbound traffic to an upstream local proxy (e.g. Clash Verge).
/// When tripped, rejects all new connections with HTTP 503 and immediately severs all active in-flight tunnels.
final class CircuitBreakerProxy: @unchecked Sendable {
    typealias AuditHandler = @Sendable (ConnectionAuditEntry) -> Void
    typealias TunnelCountHandler = @Sendable (Int) -> Void
    typealias UpstreamFailureHandler = @Sendable (String) -> Void

    private static let maxHeaderBytes = 32 * 1024
    private static let headerDelimiter = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n

    private final class OnceFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var claimed = false
        private var timer: DispatchSourceTimer?

        func attachTimer(_ timer: DispatchSourceTimer) {
            lock.withLock { self.timer = timer }
        }

        func claim() -> Bool {
            let (first, attached): (Bool, DispatchSourceTimer?) = lock.withLock {
                if claimed { return (false, nil) }
                claimed = true
                let t = timer
                timer = nil
                return (true, t)
            }
            attached?.cancel()
            return first
        }
    }

    private final class TunnelPair: @unchecked Sendable {
        let client: NWConnection
        let upstream: NWConnection?
        init(client: NWConnection, upstream: NWConnection?) {
            self.client = client
            self.upstream = upstream
        }
        func cancel() {
            client.cancel()
            upstream?.cancel()
        }
    }

    private let queue = DispatchQueue(label: "local.claude-environment-check.circuit-breaker", qos: .userInitiated)
    private let lock = NSLock()
    private var listener: NWListener?
    private var boundPort: Int?
    private var upstreamPort: Int = 0
    private var upstreamProtocol: UpstreamProxyProtocol = .httpConnect
    private var gateState: BreakerGateState = .tripped(reason: "尚未完成出口校验")
    private var activeTunnels: [UUID: TunnelPair] = [:]
    private var isStopped = false

    private let onAudit: AuditHandler
    private let onTunnelCountChange: TunnelCountHandler
    private let onUpstreamFailure: UpstreamFailureHandler

    init(
        onAudit: @escaping AuditHandler,
        onTunnelCountChange: @escaping TunnelCountHandler = { _ in },
        onUpstreamFailure: @escaping UpstreamFailureHandler = { _ in }
    ) {
        self.onAudit = onAudit
        self.onTunnelCountChange = onTunnelCountChange
        self.onUpstreamFailure = onUpstreamFailure
    }

    var listeningPort: Int? {
        lock.lock()
        defer { lock.unlock() }
        return boundPort
    }

    var currentGateState: BreakerGateState {
        lock.lock()
        defer { lock.unlock() }
        return gateState
    }

    func setGateState(_ newState: BreakerGateState) {
        var tunnelsToKill: [TunnelPair] = []
        var countChanged = false

        lock.lock()
        gateState = newState
        if case .tripped = newState, !activeTunnels.isEmpty {
            tunnelsToKill = Array(activeTunnels.values)
            activeTunnels.removeAll()
            countChanged = true
        }
        lock.unlock()

        for tunnel in tunnelsToKill {
            tunnel.cancel()
        }
        if countChanged {
            onTunnelCountChange(0)
        }
    }

    func updateUpstreamPort(_ port: Int, protocol proto: UpstreamProxyProtocol = .httpConnect) {
        lock.lock()
        upstreamPort = port
        upstreamProtocol = proto
        lock.unlock()
    }

    func start(
        preferredPort: Int = 17899,
        upstreamPort: Int,
        upstreamProtocol: UpstreamProxyProtocol = .httpConnect,
        initialState: BreakerGateState
    ) async throws -> Int {
        guard (1...65535).contains(upstreamPort) else {
            throw CircuitBreakerError.invalidUpstreamPort
        }
        stop()

        lock.withLock {
            self.isStopped = false
            self.upstreamPort = upstreamPort
            self.upstreamProtocol = upstreamProtocol
            self.gateState = initialState
        }

        let candidates: [Int]
        if (1024...65535).contains(preferredPort) {
            candidates = [preferredPort] + Array(17899...17920).filter { $0 != preferredPort }
        } else {
            candidates = Array(17899...17920)
        }

        var lastError: Error = CircuitBreakerError.noAvailablePort
        for port in candidates {
            do {
                let bound = try await bindListener(port: UInt16(port))
                lock.withLock {
                    self.boundPort = Int(bound)
                }
                return Int(bound)
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    func stop() {
        lock.lock()
        isStopped = true
        let currentListener = listener
        listener = nil
        boundPort = nil
        let tunnels = Array(activeTunnels.values)
        activeTunnels.removeAll()
        lock.unlock()

        currentListener?.newConnectionHandler = nil
        currentListener?.stateUpdateHandler = nil
        currentListener?.cancel()
        for tunnel in tunnels {
            tunnel.cancel()
        }
        onTunnelCountChange(0)
    }

    private func bindListener(port: UInt16) async throws -> UInt16 {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = NWEndpoint.hostPort(
            host: .ipv4(.loopback),
            port: NWEndpoint.Port(rawValue: port)!
        )
        let nwListener = try NWListener(using: params)

        return try await withCheckedThrowingContinuation { continuation in
            let once = OnceFlag()

            nwListener.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    guard once.claim() else { return }
                    let actualPort = nwListener.port?.rawValue ?? port
                    self?.lock.withLock {
                        self?.listener = nwListener
                    }
                    continuation.resume(returning: actualPort)
                case .failed(let err):
                    nwListener.cancel()
                    if once.claim() {
                        continuation.resume(throwing: CircuitBreakerError.listenerFailed(err.localizedDescription))
                    }
                case .cancelled:
                    if once.claim() {
                        continuation.resume(throwing: CircuitBreakerError.listenerFailed("监听器已取消"))
                    }
                default:
                    break
                }
            }

            nwListener.newConnectionHandler = { [weak self] connection in
                self?.handleIncomingConnection(connection)
            }

            nwListener.start(queue: queue)
        }
    }

    // MARK: - Client Connection Handling

    private func handleIncomingConnection(_ client: NWConnection) {
        guard isLoopbackEndpoint(client.endpoint) else {
            client.cancel()
            return
        }
        client.start(queue: queue)
        readHeaderBlock(from: client, accumulated: Data()) { [weak self] result in
            guard let self else {
                client.cancel()
                return
            }
            switch result {
            case .failure:
                client.cancel()
            case let .success((headerData, trailingData)):
                self.dispatchClientRequest(client: client, headerData: headerData, trailingData: trailingData)
            }
        }
    }

    private func dispatchClientRequest(client: NWConnection, headerData: Data, trailingData: Data) {
        let startedAt = Date()
        let startInstant = ContinuousClock.now

        // Fast local-only health check for terminal `claude-safe` wrapper (<5ms, zero upstream traffic)
        if let first = Self.firstLine(of: headerData),
           (first.hasPrefix("GET /__claude_guard_health ") || first.hasPrefix("HEAD /__claude_guard_health ")) {
            respondHealthCheck(client: client)
            return
        }

        guard let parsed = Self.parseHTTPProxyRequest(headerData) else {
            sendSimpleHTTPResponse(client: client, status: "400 Bad Request", body: "Malformed proxy request.\n")
            return
        }

        let isClaude = ConnectionAuditLog.isClaudeHost(parsed.host)

        // Block loopback targets to prevent SSRF / proxy loops
        if Self.isLoopbackOrLinkLocalHost(parsed.host) {
            sendSimpleHTTPResponse(client: client, status: "403 Forbidden", body: "Loopback targets are forbidden.\n")
            emitAudit(
                startedAt: startedAt,
                method: parsed.method,
                host: parsed.host,
                port: parsed.port,
                isClaude: isClaude,
                decision: .rejectedLoopback,
                reason: "拒绝代理访问本机回环地址",
                exitIP: nil,
                exitCountry: nil,
                bytesUp: 0,
                bytesDown: 0,
                durationMs: elapsedMs(since: startInstant)
            )
            return
        }

        // Circuit-breaker check
        let snapshotGate: BreakerGateState
        let currentUpstreamPort: Int
        let currentUpstreamProto: UpstreamProxyProtocol
        lock.lock()
        snapshotGate = gateState
        currentUpstreamPort = upstreamPort
        currentUpstreamProto = upstreamProtocol
        lock.unlock()

        switch snapshotGate {
        case .tripped(let reason):
            let body = "EnvGuard Circuit Breaker Tripped: \(reason)\n"
            sendSimpleHTTPResponse(
                client: client,
                status: "503 Service Unavailable",
                extraHeaders: ["X-Claude-EnvCheck-Breaker": "tripped"],
                body: body
            )
            emitAudit(
                startedAt: startedAt,
                method: parsed.method,
                host: parsed.host,
                port: parsed.port,
                isClaude: isClaude,
                decision: .blocked,
                reason: reason,
                exitIP: nil,
                exitCountry: nil,
                bytesUp: 0,
                bytesDown: 0,
                durationMs: elapsedMs(since: startInstant)
            )
            return

        case let .open(exitIP, exitCountry):
            if parsed.method == "CONNECT" {
                handleConnectTunnel(
                    client: client,
                    host: parsed.host,
                    port: parsed.port,
                    trailingClientBytes: trailingData,
                    upstreamPort: currentUpstreamPort,
                    upstreamProtocol: currentUpstreamProto,
                    startedAt: startedAt,
                    startInstant: startInstant,
                    isClaude: isClaude,
                    exitIP: exitIP,
                    exitCountry: exitCountry
                )
            } else {
                handlePlainHTTPForward(
                    client: client,
                    parsed: parsed,
                    rawRequest: headerData + trailingData,
                    upstreamPort: currentUpstreamPort,
                    upstreamProtocol: currentUpstreamProto,
                    startedAt: startedAt,
                    startInstant: startInstant,
                    isClaude: isClaude,
                    exitIP: exitIP,
                    exitCountry: exitCountry
                )
            }
        }
    }

    private func respondHealthCheck(client: NWConnection) {
        let (state, proto, upPort): (BreakerGateState, UpstreamProxyProtocol, Int) = lock.withLock {
            (gateState, upstreamProtocol, upstreamPort)
        }
        let esc: (String) -> String = { s in
            s.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: " ")
        }
        switch state {
        case let .open(ip, cc):
            let json = "{\"state\":\"open\",\"ip\":\"\(esc(ip ?? ""))\",\"country\":\"\(esc(cc ?? ""))\",\"upstreamPort\":\(upPort),\"upstreamProtocol\":\"\(proto.rawValue)\"}\n"
            sendSimpleHTTPResponse(
                client: client,
                status: "200 OK",
                contentType: "application/json; charset=utf-8",
                extraHeaders: ["X-Claude-EnvCheck-Breaker": "open"],
                body: json
            )
        case .tripped(let reason):
            let json = "{\"state\":\"tripped\",\"reason\":\"\(esc(reason))\",\"upstreamPort\":\(upPort),\"upstreamProtocol\":\"\(proto.rawValue)\"}\n"
            sendSimpleHTTPResponse(
                client: client,
                status: "503 Service Unavailable",
                contentType: "application/json; charset=utf-8",
                extraHeaders: ["X-Claude-EnvCheck-Breaker": "tripped"],
                body: json
            )
        }
    }

    private func handleConnectTunnel(
        client: NWConnection,
        host: String,
        port: Int,
        trailingClientBytes: Data,
        upstreamPort: Int,
        upstreamProtocol: UpstreamProxyProtocol,
        startedAt: Date,
        startInstant: ContinuousClock.Instant,
        isClaude: Bool,
        exitIP: String?,
        exitCountry: String?
    ) {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(upstreamPort)) else {
            sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Invalid upstream port.\n")
            return
        }

        let upstream = NWConnection(host: .ipv4(.loopback), port: nwPort, using: .tcp)
        let tunnelID = registerTunnel(client: client, upstream: upstream)
        let handshake = OnceFlag()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 6.0)
        timer.setEventHandler { [weak self] in
            guard handshake.claim() else { return }
            self?.unregisterTunnel(tunnelID)
            upstream.cancel()
            self?.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Upstream proxy timed out.\n")
            self?.emitAudit(
                startedAt: startedAt, method: "CONNECT", host: host, port: port, isClaude: isClaude,
                decision: .upstreamError, reason: "上游代理 127.0.0.1:\(upstreamPort) 握手超时",
                exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                durationMs: self?.elapsedMs(since: startInstant)
            )
            self?.onUpstreamFailure("上游代理 127.0.0.1:\(upstreamPort) 握手超时")
        }
        handshake.attachTimer(timer)
        timer.resume()

        let establishRelay: @Sendable (Data) -> Void = { [weak self] trailingUpstreamBytes in
            guard let self else {
                client.cancel()
                upstream.cancel()
                return
            }
            if !self.currentGateState.isOpen {
                self.unregisterTunnel(tunnelID)
                upstream.cancel()
                self.sendSimpleHTTPResponse(client: client, status: "503 Service Unavailable", body: "Breaker tripped during handshake.\n")
                return
            }
            let established = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
            client.send(content: established, completion: .contentProcessed { clientSendErr in
                if clientSendErr != nil {
                    self.unregisterTunnel(tunnelID)
                    client.cancel()
                    upstream.cancel()
                    return
                }
                self.beginRelay(
                    tunnelID: tunnelID,
                    client: client,
                    upstream: upstream,
                    initialToUpstream: trailingClientBytes,
                    initialToClient: trailingUpstreamBytes,
                    method: "CONNECT",
                    host: host,
                    port: port,
                    isClaude: isClaude,
                    startedAt: startedAt,
                    startInstant: startInstant,
                    exitIP: exitIP,
                    exitCountry: exitCountry
                )
            })
        }

        upstream.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                switch upstreamProtocol {
                case .socks5:
                    self.performSOCKS5Handshake(upstream: upstream, host: host, port: port) { result in
                        guard handshake.claim() else { return }
                        switch result {
                        case .failure(let reason):
                            self.unregisterTunnel(tunnelID)
                            upstream.cancel()
                            self.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Upstream SOCKS5 failed: \(reason)\n")
                            self.emitAudit(
                                startedAt: startedAt, method: "CONNECT", host: host, port: port, isClaude: isClaude,
                                decision: .upstreamError, reason: "上游 SOCKS5 握手失败：\(reason)",
                                exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                                durationMs: self.elapsedMs(since: startInstant)
                            )
                            self.onUpstreamFailure("上游 SOCKS5 握手失败")
                        case .success(let trailingUpstreamBytes):
                            establishRelay(trailingUpstreamBytes)
                        }
                    }

                case .httpConnect:
                    let formattedHost = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
                    let connectReq = "CONNECT \(formattedHost):\(port) HTTP/1.1\r\nHost: \(formattedHost):\(port)\r\nProxy-Connection: Keep-Alive\r\n\r\n"
                    upstream.send(content: Data(connectReq.utf8), completion: .contentProcessed { sendErr in
                        if let sendErr {
                            guard handshake.claim() else { return }
                            self.unregisterTunnel(tunnelID)
                            upstream.cancel()
                            self.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Upstream send error.\n")
                            self.emitAudit(
                                startedAt: startedAt, method: "CONNECT", host: host, port: port, isClaude: isClaude,
                                decision: .upstreamError, reason: "发送上游 CONNECT 失败：\(sendErr.localizedDescription)",
                                exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                                durationMs: self.elapsedMs(since: startInstant)
                            )
                            self.onUpstreamFailure("上游代理通信失败")
                            return
                        }

                        self.readHeaderBlock(from: upstream, accumulated: Data()) { respResult in
                            guard handshake.claim() else { return }

                            switch respResult {
                            case .failure(let err):
                                self.unregisterTunnel(tunnelID)
                                upstream.cancel()
                                self.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Upstream handshake failed.\n")
                                self.emitAudit(
                                    startedAt: startedAt, method: "CONNECT", host: host, port: port, isClaude: isClaude,
                                    decision: .upstreamError, reason: "上游代理响应异常：\(err)",
                                    exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                                    durationMs: self.elapsedMs(since: startInstant)
                                )
                                self.onUpstreamFailure("上游代理握手异常")

                            case let .success((respHeader, trailingUpstreamBytes)):
                                guard Self.isHTTP200Response(respHeader) else {
                                    let statusLine = Self.firstLine(of: respHeader) ?? "non-200"
                                    self.unregisterTunnel(tunnelID)
                                    upstream.cancel()
                                    self.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Upstream rejected CONNECT: \(statusLine)\n")
                                    self.emitAudit(
                                        startedAt: startedAt, method: "CONNECT", host: host, port: port, isClaude: isClaude,
                                        decision: .upstreamError, reason: "上游拒绝隧道：\(statusLine)",
                                        exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                                        durationMs: self.elapsedMs(since: startInstant)
                                    )
                                    return
                                }
                                establishRelay(trailingUpstreamBytes)
                            }
                        }
                    })
                }

            case .failed(let err):
                guard handshake.claim() else { return }
                self.unregisterTunnel(tunnelID)
                upstream.cancel()
                self.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Unable to connect to upstream proxy.\n")
                self.emitAudit(
                    startedAt: startedAt, method: "CONNECT", host: host, port: port, isClaude: isClaude,
                    decision: .upstreamError, reason: "无法连接上游代理 127.0.0.1:\(upstreamPort)：\(err.localizedDescription)",
                    exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                    durationMs: self.elapsedMs(since: startInstant)
                )
                self.onUpstreamFailure("无法连接上游代理 127.0.0.1:\(upstreamPort)")

            default:
                break
            }
        }
        upstream.start(queue: queue)
    }

    private func handlePlainHTTPForward(
        client: NWConnection,
        parsed: ParsedProxyRequest,
        rawRequest: Data,
        upstreamPort: Int,
        upstreamProtocol: UpstreamProxyProtocol,
        startedAt: Date,
        startInstant: ContinuousClock.Instant,
        isClaude: Bool,
        exitIP: String?,
        exitCountry: String?
    ) {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(upstreamPort)) else {
            sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Invalid upstream port.\n")
            return
        }
        let upstream = NWConnection(host: .ipv4(.loopback), port: nwPort, using: .tcp)
        let tunnelID = registerTunnel(client: client, upstream: upstream)
        let connectOnce = OnceFlag()

        upstream.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard connectOnce.claim() else { return }
                switch upstreamProtocol {
                case .httpConnect:
                    self.beginRelay(
                        tunnelID: tunnelID,
                        client: client,
                        upstream: upstream,
                        initialToUpstream: rawRequest,
                        initialToClient: Data(),
                        method: parsed.method,
                        host: parsed.host,
                        port: parsed.port,
                        isClaude: isClaude,
                        startedAt: startedAt,
                        startInstant: startInstant,
                        exitIP: exitIP,
                        exitCountry: exitCountry
                    )
                case .socks5:
                    self.performSOCKS5Handshake(upstream: upstream, host: parsed.host, port: parsed.port) { result in
                        switch result {
                        case .failure(let reason):
                            self.unregisterTunnel(tunnelID)
                            upstream.cancel()
                            self.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Upstream SOCKS5 failed: \(reason)\n")
                            self.emitAudit(
                                startedAt: startedAt, method: parsed.method, host: parsed.host, port: parsed.port, isClaude: isClaude,
                                decision: .upstreamError, reason: "上游 SOCKS5 失败：\(reason)",
                                exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                                durationMs: self.elapsedMs(since: startInstant)
                            )
                            self.onUpstreamFailure("上游 SOCKS5 连接失败")
                        case .success(let trailing):
                            let originReq = Self.rewriteProxyRequestToOriginForm(rawRequest)
                            self.beginRelay(
                                tunnelID: tunnelID,
                                client: client,
                                upstream: upstream,
                                initialToUpstream: originReq,
                                initialToClient: trailing,
                                method: parsed.method,
                                host: parsed.host,
                                port: parsed.port,
                                isClaude: isClaude,
                                startedAt: startedAt,
                                startInstant: startInstant,
                                exitIP: exitIP,
                                exitCountry: exitCountry
                            )
                        }
                    }
                }
            case .failed(let err):
                guard connectOnce.claim() else { return }
                self.unregisterTunnel(tunnelID)
                upstream.cancel()
                self.sendSimpleHTTPResponse(client: client, status: "502 Bad Gateway", body: "Upstream connect failed.\n")
                self.emitAudit(
                    startedAt: startedAt, method: parsed.method, host: parsed.host, port: parsed.port, isClaude: isClaude,
                    decision: .upstreamError, reason: "上游代理连接失败：\(err.localizedDescription)",
                    exitIP: exitIP, exitCountry: exitCountry, bytesUp: 0, bytesDown: 0,
                    durationMs: self.elapsedMs(since: startInstant)
                )
                self.onUpstreamFailure("上游代理连接失败")
            default:
                break
            }
        }
        upstream.start(queue: queue)
    }

    // MARK: - Pure Swift RFC 1928 SOCKS5 Upstream Handshake

    private enum SOCKS5HandshakeError: Error, CustomStringConvertible {
        case failed(String)
        var description: String {
            if case .failed(let s) = self { return s }
            return "unknown"
        }
    }

    static func buildSOCKS5ConnectPacket(host: String, port: Int) -> Data? {
        guard (1...65535).contains(port) else { return nil }
        let cleaned = host.trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
        var packet = Data([0x05, 0x01, 0x00])

        var v4 = in_addr()
        var v6 = in6_addr()
        if cleaned.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            packet.append(0x01)
            withUnsafeBytes(of: &v4) { packet.append(contentsOf: $0) }
        } else if cleaned.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            packet.append(0x04)
            withUnsafeBytes(of: &v6) { packet.append(contentsOf: $0) }
        } else {
            let domainBytes = Data(cleaned.utf8)
            guard !domainBytes.isEmpty, domainBytes.count <= 255 else { return nil }
            packet.append(0x03)
            packet.append(UInt8(domainBytes.count))
            packet.append(domainBytes)
        }
        packet.append(UInt8((port >> 8) & 0xFF))
        packet.append(UInt8(port & 0xFF))
        return packet
    }

    private static func rewriteProxyRequestToOriginForm(_ rawRequest: Data) -> Data {
        guard let range = rawRequest.range(of: Data([0x0D, 0x0A])) else { return rawRequest }
        guard let firstLine = String(data: rawRequest[..<range.lowerBound], encoding: .isoLatin1) else { return rawRequest }
        let parts = firstLine.split(separator: " ")
        guard parts.count >= 3,
              let url = URL(string: String(parts[1])),
              url.scheme != nil else {
            return rawRequest
        }
        var originPath = url.path.isEmpty ? "/" : url.path
        if let q = url.query { originPath += "?\(q)" }
        let rewritten = "\(parts[0]) \(originPath) \(parts[2])"
        var out = Data(rewritten.utf8)
        out.append(rawRequest[range.lowerBound...])
        return out
    }

    private func performSOCKS5Handshake(
        upstream: NWConnection,
        host: String,
        port: Int,
        completion: @escaping @Sendable (Result<Data, SOCKS5HandshakeError>) -> Void
    ) {
        guard let connectPacket = Self.buildSOCKS5ConnectPacket(host: host, port: port) else {
            completion(.failure(.failed("无效目标主机或端口")))
            return
        }
        let greeting = Data([0x05, 0x01, 0x00])
        upstream.send(content: greeting, completion: .contentProcessed { [weak self] err in
            if let err {
                completion(.failure(.failed("SOCKS5 问候发送失败：\(err.localizedDescription)")))
                return
            }
            guard let self else {
                completion(.failure(.failed("连接已释放")))
                return
            }
            self.readAtLeast(from: upstream, minimum: 2, accumulated: Data()) { greetRes in
                switch greetRes {
                case .failure(let e):
                    completion(.failure(.failed("SOCKS5 问候响应异常：\(e)")))
                case .success(let buf):
                    guard buf.count >= 2, buf[0] == 0x05, buf[1] == 0x00 else {
                        let method = buf.count >= 2 ? buf[1] : 0xFF
                        completion(.failure(.failed(method == 0xFF ? "上游 SOCKS5 需要鉴权（仅支持无鉴权本地代理）" : "上游非 SOCKS5 协议")))
                        return
                    }
                    let extraAfterGreet = Data(buf.dropFirst(2))
                    upstream.send(content: connectPacket, completion: .contentProcessed { sendErr in
                        if let sendErr {
                            completion(.failure(.failed("SOCKS5 CONNECT 发送失败：\(sendErr.localizedDescription)")))
                            return
                        }
                        self.readAtLeast(from: upstream, minimum: 4, accumulated: extraAfterGreet) { headRes in
                            switch headRes {
                            case .failure(let e):
                                completion(.failure(.failed("SOCKS5 响应头异常：\(e)")))
                            case .success(let headBuf):
                                guard headBuf[0] == 0x05 else {
                                    completion(.failure(.failed("SOCKS5 协议版本异常")))
                                    return
                                }
                                guard headBuf[1] == 0x00 else {
                                    completion(.failure(.failed("SOCKS5 上游拒绝连接 (REP=0x\(String(format: "%02X", headBuf[1])))")))
                                    return
                                }
                                let atyp = headBuf[3]
                                let afterHeader = Data(headBuf.dropFirst(4))
                                switch atyp {
                                case 0x01: // IPv4 (4) + port (2)
                                    self.readAtLeast(from: upstream, minimum: 6, accumulated: afterHeader) { r in
                                        switch r {
                                        case .failure(let e): completion(.failure(.failed("SOCKS5 IPv4 尾字节异常：\(e)")))
                                        case .success(let tail): completion(.success(Data(tail.dropFirst(6))))
                                        }
                                    }
                                case 0x04: // IPv6 (16) + port (2)
                                    self.readAtLeast(from: upstream, minimum: 18, accumulated: afterHeader) { r in
                                        switch r {
                                        case .failure(let e): completion(.failure(.failed("SOCKS5 IPv6 尾字节异常：\(e)")))
                                        case .success(let tail): completion(.success(Data(tail.dropFirst(18))))
                                        }
                                    }
                                case 0x03: // 1 len byte + domain + 2 port bytes
                                    self.readAtLeast(from: upstream, minimum: 1, accumulated: afterHeader) { lr in
                                        switch lr {
                                        case .failure(let e):
                                            completion(.failure(.failed("SOCKS5 域名长度异常：\(e)")))
                                        case .success(let lenBuf):
                                            let need = Int(lenBuf[0]) + 2
                                            self.readAtLeast(from: upstream, minimum: need, accumulated: Data(lenBuf.dropFirst(1))) { dr in
                                                switch dr {
                                                case .failure(let e): completion(.failure(.failed("SOCKS5 域名尾字节异常：\(e)")))
                                                case .success(let tail): completion(.success(Data(tail.dropFirst(need))))
                                                }
                                            }
                                        }
                                    }
                                default:
                                    completion(.failure(.failed("未知 SOCKS5 地址类型 (0x\(String(format: "%02X", atyp)))")))
                                }
                            }
                        }
                    })
                }
            }
        })
    }

    private func readAtLeast(
        from connection: NWConnection,
        minimum: Int,
        accumulated: Data,
        completion: @escaping @Sendable (Result<Data, HeaderReadError>) -> Void
    ) {
        if accumulated.count >= minimum {
            completion(.success(accumulated))
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, error in
            guard let self else {
                completion(.failure(.closed))
                return
            }
            if let error {
                completion(.failure(.transport(error.localizedDescription)))
                return
            }
            var buffer = accumulated
            if let data, !data.isEmpty {
                buffer.append(data)
            }
            if buffer.count >= minimum {
                completion(.success(buffer))
                return
            }
            if isComplete || data == nil {
                completion(.failure(.closed))
                return
            }
            self.readAtLeast(from: connection, minimum: minimum, accumulated: buffer, completion: completion)
        }
    }

    // MARK: - Bidirectional Tunnel Relay

    private final class RelayStats: @unchecked Sendable {
        let lock = NSLock()
        var bytesUp: Int64 = 0
        var bytesDown: Int64 = 0
        var finished = false
    }

    private func beginRelay(
        tunnelID: UUID,
        client: NWConnection,
        upstream: NWConnection,
        initialToUpstream: Data,
        initialToClient: Data,
        method: String,
        host: String,
        port: Int,
        isClaude: Bool,
        startedAt: Date,
        startInstant: ContinuousClock.Instant,
        exitIP: String?,
        exitCountry: String?
    ) {
        let stats = RelayStats()

        let finalize: @Sendable () -> Void = { [weak self] in
            stats.lock.lock()
            let first = !stats.finished
            stats.finished = true
            let up = stats.bytesUp
            let down = stats.bytesDown
            stats.lock.unlock()
            guard first else { return }
            self?.unregisterTunnel(tunnelID)
            client.cancel()
            upstream.cancel()
            self?.emitAudit(
                startedAt: startedAt,
                method: method,
                host: host,
                port: port,
                isClaude: isClaude,
                decision: .allowed,
                reason: nil,
                exitIP: exitIP,
                exitCountry: exitCountry,
                bytesUp: up,
                bytesDown: down,
                durationMs: self?.elapsedMs(since: startInstant)
            )
        }

        if !initialToUpstream.isEmpty {
            stats.lock.lock()
            stats.bytesUp += Int64(initialToUpstream.count)
            stats.lock.unlock()
            upstream.send(content: initialToUpstream, completion: .contentProcessed { err in
                if err != nil { finalize() }
            })
        }
        if !initialToClient.isEmpty {
            stats.lock.lock()
            stats.bytesDown += Int64(initialToClient.count)
            stats.lock.unlock()
            client.send(content: initialToClient, completion: .contentProcessed { err in
                if err != nil { finalize() }
            })
        }

        pump(from: client, to: upstream, isUpload: true, stats: stats, onClose: finalize)
        pump(from: upstream, to: client, isUpload: false, stats: stats, onClose: finalize)
    }

    private func pump(
        from source: NWConnection,
        to destination: NWConnection,
        isUpload: Bool,
        stats: RelayStats,
        onClose: @escaping @Sendable () -> Void
    ) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else {
                onClose()
                return
            }
            if let data, !data.isEmpty {
                stats.lock.lock()
                if isUpload {
                    stats.bytesUp += Int64(data.count)
                } else {
                    stats.bytesDown += Int64(data.count)
                }
                stats.lock.unlock()

                destination.send(content: data, completion: .contentProcessed { sendErr in
                    if sendErr != nil || isComplete || error != nil {
                        onClose()
                    } else {
                        self.pump(from: source, to: destination, isUpload: isUpload, stats: stats, onClose: onClose)
                    }
                })
                return
            }
            if isComplete || error != nil {
                onClose()
            } else {
                self.pump(from: source, to: destination, isUpload: isUpload, stats: stats, onClose: onClose)
            }
        }
    }

    // MARK: - Framing & Parsing Helpers

    private enum HeaderReadError: Error {
        case closed
        case tooLarge
        case transport(String)
    }

    private func readHeaderBlock(
        from connection: NWConnection,
        accumulated: Data,
        completion: @escaping @Sendable (Result<(Data, Data), HeaderReadError>) -> Void
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            guard let self else {
                completion(.failure(.closed))
                return
            }
            if let error {
                completion(.failure(.transport(error.localizedDescription)))
                return
            }
            var buffer = accumulated
            if let data, !data.isEmpty {
                buffer.append(data)
            }
            if let range = buffer.range(of: Self.headerDelimiter) {
                let header = buffer[..<range.upperBound]
                let trailing = buffer[range.upperBound...]
                completion(.success((Data(header), Data(trailing))))
                return
            }
            if buffer.count > Self.maxHeaderBytes {
                completion(.failure(.tooLarge))
                return
            }
            if isComplete || data == nil {
                completion(.failure(.closed))
                return
            }
            self.readHeaderBlock(from: connection, accumulated: buffer, completion: completion)
        }
    }

    private func sendSimpleHTTPResponse(
        client: NWConnection,
        status: String,
        contentType: String = "text/plain; charset=utf-8",
        extraHeaders: [String: String] = [:],
        body: String
    ) {
        let bodyData = Data(body.utf8)
        var headerText = "HTTP/1.1 \(status)\r\nContent-Type: \(contentType)\r\nContent-Length: \(bodyData.count)\r\nConnection: close\r\n"
        for (k, v) in extraHeaders {
            headerText += "\(k): \(v)\r\n"
        }
        headerText += "\r\n"
        var payload = Data(headerText.utf8)
        payload.append(bodyData)
        client.send(content: payload, completion: .contentProcessed { _ in
            client.cancel()
        })
    }

    private func registerTunnel(client: NWConnection, upstream: NWConnection?) -> UUID {
        let id = UUID()
        lock.lock()
        activeTunnels[id] = TunnelPair(client: client, upstream: upstream)
        let count = activeTunnels.count
        lock.unlock()
        onTunnelCountChange(count)
        return id
    }

    private func unregisterTunnel(_ id: UUID) {
        lock.lock()
        let removed = activeTunnels.removeValue(forKey: id) != nil
        let count = activeTunnels.count
        lock.unlock()
        if removed {
            onTunnelCountChange(count)
        }
    }

    private func emitAudit(
        startedAt: Date,
        method: String,
        host: String,
        port: Int,
        isClaude: Bool,
        decision: ConnectionDecision,
        reason: String?,
        exitIP: String?,
        exitCountry: String?,
        bytesUp: Int64,
        bytesDown: Int64,
        durationMs: Int?
    ) {
        let entry = ConnectionAuditEntry(
            id: UUID(),
            startedAt: startedAt,
            endedAt: Date(),
            method: method,
            host: host,
            port: port,
            isClaudeDomain: isClaude,
            decision: decision,
            reason: reason,
            exitIP: exitIP,
            exitCountry: exitCountry,
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            durationMs: durationMs
        )
        onAudit(entry)
    }

    private func elapsedMs(since start: ContinuousClock.Instant) -> Int {
        let duration = start.duration(to: .now)
        let ms = Double(duration.components.seconds) * 1000.0
            + Double(duration.components.attoseconds) / 1_000_000_000_000_000.0
        return max(1, Int(ms.rounded()))
    }

    private func isLoopbackEndpoint(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return true }
        switch host {
        case .ipv4(let addr):
            return addr == .loopback || addr.debugDescription.hasPrefix("127.")
        case .ipv6(let addr):
            return addr == .loopback
        case .name(let name, _):
            return name == "localhost" || name == "127.0.0.1" || name == "::1"
        @unknown default:
            return false
        }
    }

    struct ParsedProxyRequest: Equatable, Sendable {
        let method: String
        let host: String
        let port: Int
    }

    static func parseHTTPProxyRequest(_ headerData: Data) -> ParsedProxyRequest? {
        guard let text = String(data: headerData, encoding: .utf8) ?? String(data: headerData, encoding: .isoLatin1) else {
            return nil
        }
        let lines = text.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else { return nil }
        let method = String(parts[0]).uppercased()
        let target = String(parts[1])

        if method == "CONNECT" {
            if target.hasPrefix("["), let closeBracket = target.firstIndex(of: "]") {
                let host = String(target[target.index(after: target.startIndex)..<closeBracket])
                let remainder = target[target.index(after: closeBracket)...]
                let port = remainder.hasPrefix(":") ? (Int(remainder.dropFirst()) ?? 443) : 443
                guard !host.isEmpty, (1...65535).contains(port) else { return nil }
                return ParsedProxyRequest(method: method, host: host, port: port)
            }
            if let colon = target.lastIndex(of: ":") {
                let host = String(target[..<colon])
                let port = Int(target[target.index(after: colon)...]) ?? 443
                guard !host.isEmpty, (1...65535).contains(port) else { return nil }
                return ParsedProxyRequest(method: method, host: host, port: port)
            }
            return target.isEmpty ? nil : ParsedProxyRequest(method: method, host: target, port: 443)
        }

        if let url = URL(string: target), let host = url.host, !host.isEmpty {
            let defaultPort = (url.scheme?.lowercased() == "https") ? 443 : 80
            return ParsedProxyRequest(method: method, host: host, port: url.port ?? defaultPort)
        }

        // Fallback to Host header
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            if name == "host" {
                let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                if let sep = value.lastIndex(of: ":"), let port = Int(value[value.index(after: sep)...]) {
                    let host = String(value[..<sep])
                    if !host.isEmpty { return ParsedProxyRequest(method: method, host: host, port: port) }
                } else if !value.isEmpty {
                    return ParsedProxyRequest(method: method, host: value, port: 80)
                }
            }
        }
        return nil
    }

    static func isLoopbackOrLinkLocalHost(_ host: String) -> Bool {
        let lower = host.trimmingCharacters(in: CharacterSet(charactersIn: "[] ")).lowercased()
        if lower == "localhost" || lower.hasSuffix(".localhost") || lower == "0.0.0.0" || lower == "::1" || lower == "::" {
            return true
        }
        if lower.hasPrefix("127.") || lower.hasPrefix("169.254.") || lower.hasPrefix("fe80:") {
            return true
        }
        return false
    }

    static func isHTTP200Response(_ headerData: Data) -> Bool {
        guard let line = firstLine(of: headerData) else { return false }
        let parts = line.split(separator: " ")
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/1.") else { return false }
        return parts[1] == "200"
    }

    static func firstLine(of data: Data) -> String? {
        guard let text = String(data: data, encoding: .isoLatin1) else { return nil }
        return text.components(separatedBy: "\r\n").first
    }
}
