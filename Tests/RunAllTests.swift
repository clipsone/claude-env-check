import Foundation
import Network

final class TestOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool {
        lock.withLock {
            if done { return false }
            done = true
            return true
        }
    }
}

final class MockUpstreamConnectServer: @unchecked Sendable {
    private let queue = DispatchQueue(label: "tests.mock-upstream")
    private var listener: NWListener?

    func start() async throws -> Int {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: .any)
        let l = try NWListener(using: params)
        return try await withCheckedThrowingContinuation { cont in
            let once = TestOnce()
            l.stateUpdateHandler = { [weak self] st in
                switch st {
                case .ready:
                    if once.claim() {
                        self?.listener = l
                        cont.resume(returning: Int(l.port!.rawValue))
                    }
                case .failed(let e):
                    if once.claim() { cont.resume(throwing: e) }
                default: break
                }
            }
            l.newConnectionHandler = { conn in
                conn.start(queue: self.queue)
                conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                    guard let data, let text = String(data: data, encoding: .utf8), text.hasPrefix("CONNECT ") else {
                        conn.cancel()
                        return
                    }
                    conn.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8), completion: .contentProcessed { _ in
                        Self.echoLoop(conn)
                    })
                }
            }
            l.start(queue: queue)
        }
    }

    private static func echoLoop(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, err in
            if let data, !data.isEmpty {
                var resp = Data("echo:".utf8)
                resp.append(data)
                conn.send(content: resp, completion: .contentProcessed { sendErr in
                    if sendErr != nil || isComplete || err != nil {
                        conn.cancel()
                    } else {
                        echoLoop(conn)
                    }
                })
            } else {
                conn.cancel()
            }
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }
}

func sendRawTCP(port: Int, payload: String, followUp: String? = nil) async throws -> (first: String, second: String?) {
    let conn = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: UInt16(port))!, using: .tcp)
    let q = DispatchQueue(label: "tests.client.\(UUID().uuidString)")

    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
        let once = TestOnce()
        conn.stateUpdateHandler = { st in
            switch st {
            case .ready:
                if once.claim() { cont.resume() }
            case .failed(let e):
                if once.claim() { cont.resume(throwing: e) }
            default: break
            }
        }
        conn.start(queue: q)
    }
    defer { conn.cancel() }

    func sendText(_ s: String) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: Data(s.utf8), completion: .contentProcessed { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    func recvText() async throws -> String {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, _, err in
                if let err { cont.resume(throwing: err) }
                else { cont.resume(returning: String(decoding: data ?? Data(), as: UTF8.self)) }
            }
        }
    }

    try await sendText(payload)
    let first = try await recvText()
    if let followUp {
        try await sendText(followUp)
        let second = try await recvText()
        return (first, second)
    }
    return (first, nil)
}

@main
struct RunAllTests {
    nonisolated(unsafe) static var passedCount = 0

    static func check(_ cond: Bool, _ msg: String) {
        if !cond {
            fputs("FAIL: \(msg)\n", stderr)
            exit(1)
        }
        passedCount += 1
    }

    static func main() async {
        let liveMode = CommandLine.arguments.contains("--live")
        let tmpRoot = FileManager.default.temporaryDirectory.appendingPathComponent("claude-envcheck-suite-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpRoot) }

        testPhase1RegionsAndIntelligence(tmpRoot: tmpRoot)
        await testPhase1ExitHistory(tmpRoot: tmpRoot)
        await testPhase2CircuitBreakerAndProtection(tmpRoot: tmpRoot)
        await testPhase3ClashSymbiosisAndLocale(tmpRoot: tmpRoot)
        testPhase4WorkbenchAndUpdateChecker(tmpRoot: tmpRoot)
        testPhase4LazyVergeScriptInstaller(tmpRoot: tmpRoot)

        print("PASS: All \(passedCount) assertions succeeded across Phases 1–4 + v1.1!")

        if liveMode {
            await runLiveSmokeChecks(tmpRoot: tmpRoot)
        }
    }

    // MARK: - Phase 1 Tests

    static func testPhase1RegionsAndIntelligence(tmpRoot: URL) {
        check(ClaudeRegions.supportedCodes.count == 185, "Anthropic whitelist must contain 185 codes")
        for okCode in ["US", "JP", "KR", "SG", "TW", "GB", "DE", "FR", "CA", "NL", "AU"] {
            check(ClaudeRegions.support(for: okCode) == .supported, "\(okCode) must be supported")
        }
        for badCode in ["CN", "HK", "MO", "RU", "IR", "KP", "BY"] {
            check(ClaudeRegions.support(for: badCode) == .unsupported, "\(badCode) must be unsupported")
        }
        check(ClaudeRegions.support(for: "??") == .unknown, "Invalid code must be unknown")

        // Unified ASN classifier + Google Fiber residential exception + RIR placeholder filter
        check(ExitClassifier.classify(asn: 16509, org: "Amazon.com") == .hosting, "AWS must be hosting")
        check(ExitClassifier.classify(asn: 36352, org: "ColoCrossing") == .hosting, "AS36352 must be hosting")
        check(ExitClassifier.classify(asn: 13335, org: "Cloudflare") == .hosting, "Cloudflare must be hosting")
        check(ExitClassifier.classify(asn: 16591, org: "Google Fiber Inc.") == .residential, "Google Fiber must be residential")
        check(ExitClassifier.classify(asn: 7922, org: "Comcast Cable") == .residential, "Comcast must be residential")
        check(ExitClassifier.classify(asn: nil, org: "Regional Carrier XYZ") == .unknown, "Unknown org must not guess")
        check(ExitClassifier.isRIRPlaceholder("Asia Pacific Network Information Centre"), "APNIC must be treated as RIR placeholder")

        // Fake-IP, Public IP, and Akamai TXT parsing
        check(ExitProbes.isFakeIP("198.18.0.1"), "198.18.0.1 is Fake-IP")
        check(ExitProbes.isFakeIP("198.19.255.254"), "198.19.255.254 is Fake-IP")
        check(!ExitProbes.isFakeIP("198.20.0.1"), "198.20.0.1 is not Fake-IP")
        check(!ExitProbes.isPublicIP("198.18.0.2"), "Fake-IP is not public")
        check(!ExitProbes.isPublicIP("100.64.0.1"), "CGNAT is not public")
        check(ExitProbes.isPublicIP("1.1.1.1"), "1.1.1.1 is public")
        check(ExitProbes.isPublicIP("2606:4700:4700::1111"), "Public IPv6")
        check(!ExitProbes.isPublicIP("fe80::1"), "Link-local IPv6 is not public")

        let aka = ExitProbes.parseAkamaiWhoami(["ip", "183.47.124.252", "ecs", "14.216.65.0/24/24", "ns", "183.47.124.252"])
        check(aka.ns == "183.47.124.252" && aka.ecsSubnet == "14.216.65.0/24/24", "Akamai whoami parse")

        // NO_PROXY & localhost port extraction
        check(ClaudeCodeAudit.isDangerousNoProxyToken("*"), "* bypasses proxy")
        check(ClaudeCodeAudit.isDangerousNoProxyToken(".anthropic.com"), ".anthropic.com bypasses proxy")
        check(ClaudeCodeAudit.isDangerousNoProxyToken("claude.ai"), "claude.ai bypasses proxy")
        check(!ClaudeCodeAudit.isDangerousNoProxyToken("127.0.0.1"), "127.0.0.1 is safe in NO_PROXY")
        check(ClaudeCodeAudit.extractLocalhostPort(from: "http://127.0.0.1:7897") == 7897, "localhost port parse")
        check(ClaudeCodeAudit.extractLocalhostPort(from: "http://proxy.corp.local:8080") == nil, "remote proxy not localhost")
        _ = tmpRoot
    }

    static func testPhase1ExitHistory(tmpRoot: URL) async {
        let store = ExitHistoryStore(stateDirectory: tmpRoot.appendingPathComponent("history"))
        let now = Date()
        let s1 = await store.record(ExitSample(capturedAt: now.addingTimeInterval(-3600), ip: "1.1.1.1", countryCode: "CN", asn: 4134, org: "ChinaNet", networkKind: .residential, probePath: "系统网络路径"))
        check(s1.sampleCount == 1 && s1.countryChanges == 0 && s1.guardedCountryChanges == 0, "Initial history count")

        // Single switch from direct system path (CN) -> guarded proxy (US) should be caution, not danger
        let s2 = await store.record(ExitSample(capturedAt: now.addingTimeInterval(-1800), ip: "2.2.2.2", countryCode: "US", asn: 7922, org: "Comcast", networkKind: .residential, probePath: "保护代理 127.0.0.1:17899"))
        check(s2.sampleCount == 2 && s2.uniqueIPCount == 2 && s2.ipChanges == 1 && s2.countryChanges == 1 && s2.guardedCountryChanges == 0, "Single direct->proxy switch has 0 guarded changes")
        let r2 = Diagnostics.buildExitDriftReading(summary: s2)
        check(r2.severity == .caution, "Single historical country switch should be caution, not danger")

        // Subsequent country jump while guarded (US -> JP) must escalate to danger
        let s3 = await store.record(ExitSample(capturedAt: now, ip: "3.3.3.3", countryCode: "JP", asn: 4713, org: "NTT", networkKind: .residential, probePath: "熔断守卫 127.0.0.1:17899"))
        check(s3.countryChanges == 2 && s3.guardedCountryChanges == 1, "Guarded cross-country drift must be counted")
        let r3 = Diagnostics.buildExitDriftReading(summary: s3)
        check(r3.severity == .danger, "Guarded country jump must be danger")

        // Timezone reading must honor Claude Code process-level TZ alignment
        let taipei = TimeZone(identifier: "Asia/Taipei")!
        let tzWithoutProcess = Diagnostics.buildTimeZoneReading(
            localTZ: taipei, offsetLabel: "+08:00", exitTZID: "America/New_York", processTZ: nil, capturedAt: now
        )
        check(tzWithoutProcess.severity == .caution, "Unaligned Taipei vs New York must be caution")

        let tzWithProcess = Diagnostics.buildTimeZoneReading(
            localTZ: taipei, offsetLabel: "+08:00", exitTZID: "America/New_York", processTZ: "America/New_York", capturedAt: now
        )
        check(tzWithProcess.severity == .ok, "Aligned process TZ=America/New_York must turn timezone reading ok")
        check(tzWithProcess.value.contains("进程已对齐 America/New_York"), "Timezone reading should display process alignment")
    }

    // MARK: - Phase 2 Tests

    static func testPhase2CircuitBreakerAndProtection(tmpRoot: URL) async {
        let auditLog = ConnectionAuditLog(stateDirectory: tmpRoot.appendingPathComponent("audit"))
        let upstream = MockUpstreamConnectServer()
        do {
            let upPort = try await upstream.start()
            defer { upstream.stop() }

            let proxy = CircuitBreakerProxy(onAudit: { entry in
                Task { _ = await auditLog.append(entry) }
            })
            let guardPort = try await proxy.start(
                preferredPort: 17918,
                upstreamPort: upPort,
                initialState: .open(exitIP: "1.2.3.4", countryCode: "US")
            )
            defer { proxy.stop() }

            // 1. Open gate CONNECT relay
            let okRes = try await sendRawTCP(
                port: guardPort,
                payload: "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n",
                followUp: "ping-v100"
            )
            check(okRes.first.hasPrefix("HTTP/1.1 200"), "Open CONNECT must return 200")
            check(okRes.second == "echo:ping-v100", "Bidirectional tunnel echo")

            // 2. Loopback SSRF block
            let ssrfRes = try await sendRawTCP(
                port: guardPort,
                payload: "CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:22\r\n\r\n"
            )
            check(ssrfRes.first.hasPrefix("HTTP/1.1 403"), "Loopback target must be blocked with 403")

            // 3. Active in-flight tunnel severed immediately when breaker trips
            let liveConn = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: UInt16(guardPort))!, using: .tcp)
            let q = DispatchQueue(label: "tests.live-tunnel")
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let once = TestOnce()
                liveConn.stateUpdateHandler = { st in
                    if case .ready = st, once.claim() { cont.resume() }
                }
                liveConn.start(queue: q)
            }
            liveConn.send(content: Data("CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n".utf8), completion: .contentProcessed { _ in })
            let estab: String = try await withCheckedThrowingContinuation { cont in
                liveConn.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, _ in
                    cont.resume(returning: String(decoding: data ?? Data(), as: UTF8.self))
                }
            }
            check(estab.hasPrefix("HTTP/1.1 200"), "Active tunnel established")

            proxy.setGateState(.tripped(reason: "漂移至不支持地区 HK"))
            let severed: Bool = await withCheckedContinuation { cont in
                let once = TestOnce()
                liveConn.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, isComplete, err in
                    if once.claim() { cont.resume(returning: isComplete || err != nil || (data?.isEmpty ?? true)) }
                }
                q.asyncAfter(deadline: .now() + 2.0) {
                    if once.claim() { cont.resume(returning: false) }
                }
            }
            liveConn.cancel()
            check(severed, "Active tunnel must sever immediately on circuit breaker trip")

            // 4. Tripped gate rejects new connections with 503 + header
            let trippedRes = try await sendRawTCP(
                port: guardPort,
                payload: "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n"
            )
            check(trippedRes.first.hasPrefix("HTTP/1.1 503") && trippedRes.first.contains("X-Claude-EnvCheck-Breaker: tripped"), "Tripped gate must return 503")

            try? await Task.sleep(nanoseconds: 200_000_000)
            let snap = await auditLog.snapshot()
            check(snap.stats.allowed >= 2 && snap.stats.blocked >= 2, "Audit counters mismatch")
            let csv = await auditLog.exportCSV()
            check(csv.contains("api.anthropic.com") && csv.contains("blocked"), "Audit CSV export")
            check((await auditLog.exportJSON()) != nil, "Audit JSON export")
        } catch {
            check(false, "CircuitBreaker test threw: \(error)")
        }
    }

    // MARK: - Phase 3 Tests

    static func testPhase3ClashSymbiosisAndLocale(tmpRoot: URL) async {
        let yaml = """
        mixed-port: 7897
        external-controller-unix: /var/run/clash-verge-service/users/501/verge-mihomo.sock
        secret: "tok123"
        """
        let parsed = ProxyClientDiscovery.parseSimpleTopLevelYAML(yaml)
        check(parsed["mixed-port"] == "7897" && parsed["secret"] == "tok123", "YAML top-level parser")
        let hp = ProxyClientDiscovery.parseControllerHostPort("0.0.0.0:9097")
        check(hp?.0 == "127.0.0.1" && hp?.1 == 9097, "Controller host normalization")

        let chunked = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nping\r\n4\r\npong\r\n0\r\n\r\n".utf8)
        let (code, body) = try! ClashControllerClient.parseHTTPResponse(chunked)
        check(code == 200 && String(decoding: body, as: UTF8.self) == "pingpong", "Chunked HTTP decoder")

        let groups: [String: ClashProxyGroupInfo] = [
            "AI": ClashProxyGroupInfo(name: "AI", type: "Selector", current: "Auto", candidates: ["Auto", "US-1"]),
            "Auto": ClashProxyGroupInfo(name: "Auto", type: "URLTest", current: "US-2", candidates: ["US-1", "US-2"]),
        ]
        let rules: [[String: Any]] = [["type": "DOMAIN-SUFFIX", "payload": "anthropic.com", "proxy": "AI"]]
        let resolved = ClashControllerClient.resolveClaudeRoute(mode: "rule", rules: rules, groups: groups)
        check(resolved?.hasDynamicGroupInChain == true && resolved?.leafNode == "US-2", "Dynamic group drift detection")

        for region in ClaudeRegions.supportedCodes {
            let p = ClaudeRegions.recommendedProcessLocale(countryCode: region, geoTimeZone: nil)
            check(!p.timeZone.isEmpty && !p.lang.isEmpty, "Process locale coverage for \(region)")
        }

        // ClashProtection v3 process-level TZ/LANG inject + atomic sync terminate restore
        let settingsURL = tmpRoot.appendingPathComponent(".claude/settings.json")
        let stateDir = tmpRoot.appendingPathComponent("prot-state")
        try! FileManager.default.createDirectory(at: settingsURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! Data("{\"env\":{\"USER_CUSTOM\":\"stay\",\"TZ\":\"Asia/Taipei\"}}\n".utf8).write(to: settingsURL)

        let prot = ClashProtection(settings: settingsURL, stateDirectory: stateDir)
        try! await prot.start(
            port: 17899,
            mode: .guardProxy,
            upstreamPort: 7897,
            extraEnv: ["TZ": "America/Los_Angeles", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"]
        )
        let restored = ClashProtection.restoreGuardModeOnTerminateSync(stateDirectory: stateDir)
        check(restored, "Guard mode sync termination restore must succeed")
        let afterJSON = (try! JSONSerialization.jsonObject(with: Data(contentsOf: settingsURL))) as! [String: Any]
        let afterEnv = afterJSON["env"] as! [String: String]
        check(afterEnv["TZ"] == "Asia/Taipei" && afterEnv["LANG"] == nil && afterEnv["HTTP_PROXY"] == nil && afterEnv["USER_CUSTOM"] == "stay", "Restore must revert TZ/LANG/Proxy and preserve user keys")

        let jsOverride = ClashOverrideGenerator.generateVergeJavaScript()
        check(jsOverride.contains("Claude-Pin") && jsOverride.contains("nameserver-policy"), "Verge JS override generator")
    }

    // MARK: - Phase 4 Tests

    static func testPhase4WorkbenchAndUpdateChecker(tmpRoot: URL) {
        // 1. Isolated Browser Launch Spec (anti-leak flags, remote DNS, process TZ/LANG, zero bookmark copy)
        let fakeBrowser = DiscoveredBrowser(
            id: "chrome",
            name: "Google Chrome",
            bundleID: "com.google.Chrome",
            appPath: "/Applications/Google Chrome.app",
            executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            version: "130.0"
        )
        let spec = IsolatedBrowserLauncher.buildLaunchSpec(
            browser: fakeBrowser,
            proxyPort: 17899,
            countryCode: "JP",
            geoTimeZone: "Asia/Tokyo",
            startURL: "https://claude.ai",
            stateDirectory: tmpRoot
        )
        check(spec.arguments.contains("--disable-quic"), "Must disable QUIC")
        check(spec.arguments.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"), "Must enforce native WebRTC policy")
        check(spec.arguments.contains("--proxy-server=http://127.0.0.1:17899"), "Must route via proxy port")
        check(!spec.arguments.contains { $0.hasPrefix("--host-resolver-rules=") }, "Must omit --host-resolver-rules to avoid Chrome unsupported-flag infobar")
        check(spec.arguments.contains("--lang=ja-JP"), "Must pass BCP-47 --lang")
        check(spec.environment["TZ"] == "Asia/Tokyo" && spec.environment["LANG"] == "ja_JP.UTF-8" && spec.environment["LANGUAGE"] == "ja-JP:ja", "Must inject process-level TZ/LANG/LANGUAGE")
        check(!FileManager.default.fileExists(atPath: URL(fileURLWithPath: spec.profileDirectory).appendingPathComponent("Default/Bookmarks").path), "Must NEVER silently copy user bookmarks")

        // 1b. Profile language preference merge preserves existing keys & sets intl.accept_languages
        let profDir = tmpRoot.appendingPathComponent("lang-prof-test", isDirectory: true)
        let defDir = profDir.appendingPathComponent("Default", isDirectory: true)
        try! FileManager.default.createDirectory(at: defDir, withIntermediateDirectories: true)
        try! Data("{\"profile\":{\"name\":\"KeepMe\"}}".utf8).write(to: defDir.appendingPathComponent("Preferences"))
        try! IsolatedBrowserLauncher.applyProfileLanguagePreferences(profileDirectory: profDir, bcp47Language: "en-US")
        let prefObj = (try! JSONSerialization.jsonObject(with: Data(contentsOf: defDir.appendingPathComponent("Preferences")))) as! [String: Any]
        let intlObj = prefObj["intl"] as? [String: Any]
        let profileObj = prefObj["profile"] as? [String: Any]
        check(intlObj?["accept_languages"] as? String == "en-US,en" && intlObj?["selected_languages"] as? String == "en-US,en", "Profile Preferences must set intl.accept_languages")
        check(profileObj?["name"] as? String == "KeepMe", "Profile Preferences merge must preserve existing user keys")

        // 1c. Claude Desktop aligned launch spec locks Chromium renderer + Electron Node to circuit breaker proxy
        let desktopSpec = ClaudeDesktopManager.buildLaunchSpec(
            proxyPort: 17899,
            countryCode: "US",
            geoTimeZone: "America/New_York",
            useIsolatedProfile: true,
            stateDirectory: tmpRoot
        )
        check(desktopSpec.arguments.contains("--proxy-server=http://127.0.0.1:17899"), "Desktop must pass --proxy-server to lock Chromium renderer")
        check(desktopSpec.arguments.contains("--disable-quic"), "Desktop must disable QUIC")
        check(desktopSpec.arguments.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"), "Desktop must block non-proxied WebRTC UDP")
        check(desktopSpec.arguments.contains("--lang=en-US"), "Desktop must pass --lang=en-US")
        check(desktopSpec.environment["TZ"] == "America/New_York" && desktopSpec.environment["LANGUAGE"] == "en-US:en", "Desktop must align TZ and LANGUAGE")
        check(desktopSpec.environment["HTTPS_PROXY"] == "http://127.0.0.1:17899" && desktopSpec.environment["NODE_USE_ENV_PROXY"] == "1", "Desktop must lock Node main process proxy")

        // 2. Anti-symlink path safety verification (reject symlink escape, allow normal path inside home)
        let fakeHome = tmpRoot.appendingPathComponent("fake-home", isDirectory: true)
        let safeDir = fakeHome.appendingPathComponent("Library/Caches/Claude", isDirectory: true)
        try! FileManager.default.createDirectory(at: safeDir, withIntermediateDirectories: true)
        try! Data("test".utf8).write(to: safeDir.appendingPathComponent("sample.bin"))
        var safePassed = false
        do {
            try PathSafety.verifyNoSymlinks(at: safeDir, within: fakeHome)
            safePassed = true
        } catch {}
        check(safePassed, "Normal directory inside home must pass PathSafety")

        let outsideTarget = tmpRoot.appendingPathComponent("outside-secret")
        try! Data("secret".utf8).write(to: outsideTarget)
        let symlinkPath = fakeHome.appendingPathComponent("Library/Caches/EvilLink")
        try! FileManager.default.createSymbolicLink(at: symlinkPath, withDestinationURL: outsideTarget)
        var symlinkBlocked = false
        do {
            try PathSafety.verifyNoSymlinks(at: symlinkPath, within: fakeHome)
        } catch {
            symlinkBlocked = true
        }
        check(symlinkBlocked, "Symlink inside cleanup target MUST be rejected by PathSafety!")

        // 3. SemVer & Passive GitHub Release Parser
        check(SemVer("1.2.0")! > SemVer("1.0.9")!, "SemVer minor comparison")
        check(SemVer("v2.0.0")! > SemVer("1.99.99")!, "SemVer major comparison")
        check(UpdateChecker.isValidRepoSlug("user-name/claude-env-check"), "Valid repo slug")
        check(!UpdateChecker.isValidRepoSlug("https://github.com/a/b"), "Reject URL as repo slug")

        let releaseJSON = Data("""
        {
          "tag_name": "v1.2.0",
          "draft": false,
          "prerelease": false,
          "html_url": "https://github.com/example/claude-env-check/releases/tag/v1.2.0",
          "body": "Release notes",
          "assets": [{"name": "Claude-Environment-Check-1.2.0-arm64.dmg"}]
        }
        """.utf8)
        let parsedRel = try! UpdateChecker.parseReleaseJSON(releaseJSON, repoSlug: "example/claude-env-check", currentVersion: "1.0.0")
        if case let .updateAvailable(ver, url, asset, _) = parsedRel.status {
            check(ver == SemVer("1.2.0")! && url.host == "github.com" && asset == "Claude-Environment-Check-1.2.0-arm64.dmg", "Update available parse")
        } else {
            check(false, "Expected updateAvailable status")
        }
        let upToDate = try! UpdateChecker.parseReleaseJSON(releaseJSON, repoSlug: "example/claude-env-check", currentVersion: "1.2.0")
        check(upToDate.status == .upToDate, "Equal version must report upToDate")
    }

    static func testPhase4LazyVergeScriptInstaller(tmpRoot: URL) {
        let fakeHome = tmpRoot.appendingPathComponent("verge-home", isDirectory: true)
        let vergeDir = fakeHome.appendingPathComponent("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev", isDirectory: true)
        let profilesDir = vergeDir.appendingPathComponent("profiles", isDirectory: true)
        let scriptURL = profilesDir.appendingPathComponent("Script.js")
        let backupURL = fakeHome.appendingPathComponent("state/clash-verge-script-backup.json")
        try! FileManager.default.createDirectory(at: profilesDir, withIntermediateDirectories: true)

        // 1. Default Clash Verge stub detection + 1-click install + exact byte-for-byte restore
        let stub = "// Define main function (script entry)\n\nfunction main(config, profileName) {\n  return config;\n}\n"
        try! Data(stub.utf8).write(to: scriptURL)
        check(ClashVergeScriptInstaller.isDefaultStubScript(stub), "Default stub must be recognized")
        check(ClashVergeScriptInstaller.inspectStatus(vergeDir: vergeDir, backupFile: backupURL) == .notInstalled(hasExistingCustomScript: false), "Initial status must be notInstalled(false)")

        let chained1 = try! ClashVergeScriptInstaller.install(preferredNodeName: "US-LA-01", vergeDir: vergeDir, backupFile: backupURL, home: fakeHome)
        check(!chained1, "Default stub should not need custom chaining")
        let written1 = try! String(contentsOf: scriptURL, encoding: .utf8)
        check(written1.contains(ClashVergeScriptInstaller.managedMarkerStart), "Managed start marker present")
        check(written1.contains("const PREFERRED_NODE = \"US-LA-01\";"), "Preferred node pinned automatically")
        check(written1.contains("\"geosite:cn\": cnDoh") && written1.contains("\"+.akahelp.net\": remoteDoh"), "DNS/ECS anti-leak policy present")
        check(ClashVergeScriptInstaller.inspectStatus(vergeDir: vergeDir, backupFile: backupURL) == .installed(chainedCustomScript: false, activeInKernel: false), "Status after install")

        try! ClashVergeScriptInstaller.restore(vergeDir: vergeDir, backupFile: backupURL, home: fakeHome)
        let restored1 = try! String(contentsOf: scriptURL, encoding: .utf8)
        check(restored1 == stub, "Exact byte-for-byte restore of default stub")
        check(!FileManager.default.fileExists(atPath: backupURL.path), "Backup removed after restore")

        // 2. Existing custom user Script.js -> safely chained & preserved across reinstall + restored verbatim
        let customScript = "function main(config, profileName) {\n  config.__customFlag = 42;\n  return config;\n}\n"
        try! Data(customScript.utf8).write(to: scriptURL)
        check(!ClashVergeScriptInstaller.isDefaultStubScript(customScript), "Custom script must not be treated as default stub")
        check(ClashVergeScriptInstaller.inspectStatus(vergeDir: vergeDir, backupFile: backupURL) == .notInstalled(hasExistingCustomScript: true), "Custom script status detected")

        let chained2 = try! ClashVergeScriptInstaller.install(preferredNodeName: "JP-Tokyo", vergeDir: vergeDir, backupFile: backupURL, home: fakeHome)
        check(chained2, "Custom user script MUST be chained")
        let written2 = try! String(contentsOf: scriptURL, encoding: .utf8)
        check(written2.contains("__claudeOriginalUserMain") && written2.contains("config.__customFlag = 42;"), "Custom logic preserved in chain")

        // Re-install update should still chain original custom script (not double-wrap managed script)
        let chained3 = try! ClashVergeScriptInstaller.install(preferredNodeName: "SG-01", vergeDir: vergeDir, backupFile: backupURL, home: fakeHome)
        check(chained3, "Re-install keeps custom chaining flag")
        let written3 = try! String(contentsOf: scriptURL, encoding: .utf8)
        check(written3.components(separatedBy: "__claudeOriginalUserMain").count == 3, "Must NOT double-wrap custom script on re-install")

        try! ClashVergeScriptInstaller.restore(vergeDir: vergeDir, backupFile: backupURL, home: fakeHome)
        let restored2 = try! String(contentsOf: scriptURL, encoding: .utf8)
        check(restored2 == customScript, "Exact restore of custom user Script.js")

        // 3. Anti-symlink safety on Script.js
        let outside = tmpRoot.appendingPathComponent("outside.js")
        try! Data("outside".utf8).write(to: outside)
        try! FileManager.default.removeItem(at: scriptURL)
        try! FileManager.default.createSymbolicLink(at: scriptURL, withDestinationURL: outside)
        var rejected = false
        do {
            _ = try ClashVergeScriptInstaller.install(vergeDir: vergeDir, backupFile: backupURL, home: fakeHome)
        } catch {
            rejected = true
        }
        check(rejected, "Symlink Script.js MUST be rejected")
    }

    // MARK: - Optional Live Smoke Checks (--live)

    @MainActor
    static func runLiveSmokeChecks(tmpRoot: URL) async {
        print("--- Running live macOS smoke checks ---")
        let browsers = IsolatedBrowserLauncher.discoverBrowsers()
        print("Installed Chromium browsers: \(browsers.map { "\($0.name) (\($0.version ?? "?"))" }.joined(separator: ", "))")
        let desktop = await ClaudeDesktopManager.inspect()
        print("Claude Desktop: installed=\(desktop.installed) version=\(desktop.version ?? "n/a") running=\(desktop.running) items=\(desktop.existingItems.count) bytes=\(desktop.totalBytes)")
        let clients = await ProxyClientDiscovery.scanRunningClients()
        print("Running proxy clients: \(clients.map { "\($0.clientName) :\($0.port) [\($0.protocols.label)]" }.joined(separator: ", "))")
        let snap = await Diagnostics.capture(online: true, route: .system, historyStore: ExitHistoryStore(stateDirectory: tmpRoot.appendingPathComponent("live-hist")))
        print("Live verdict: \(snap.verdict.headline)")
    }
}
