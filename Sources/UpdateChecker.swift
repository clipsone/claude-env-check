import Foundation

struct SemVer: Comparable, Equatable, Sendable, CustomStringConvertible {
    let major: Int
    let minor: Int
    let patch: Int

    var description: String { "\(major).\(minor).\(patch)" }

    init?(_ raw: String) {
        let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "^[vV]", with: "", options: .regularExpression)
        let core = cleaned.split(separator: "-").first.map(String.init) ?? cleaned
        let parts = core.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 3, parts.allSatisfy({ $0 >= 0 }) else { return nil }
        self.major = parts[0]
        self.minor = parts[1]
        self.patch = parts[2]
    }

    static func < (lhs: SemVer, rhs: SemVer) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        return lhs.patch < rhs.patch
    }
}

struct ReleaseCheckResult: Equatable, Sendable {
    enum Status: Equatable, Sendable {
        case upToDate
        case updateAvailable(latest: SemVer, releaseURL: URL, assetName: String?, notes: String?)
        case noReleases
    }

    let currentVersion: String
    let repoSlug: String
    let status: Status
    let checkedAt: Date
}

enum UpdateCheckError: LocalizedError {
    case invalidRepoSlug
    case responseTooLarge
    case httpError(Int)
    case invalidPayload

    var errorDescription: String? {
        switch self {
        case .invalidRepoSlug: "GitHub 仓库格式需为 owner/repo（例如 myname/claude-env-check）。"
        case .responseTooLarge: "远端发布响应超过安全上限（512 KB）。"
        case .httpError(let code): "GitHub API 返回 HTTP \(code)。"
        case .invalidPayload: "未能解析 GitHub Release 元数据。"
        }
    }
}

/// Passive, user-initiated GitHub Releases update checker.
/// Never auto-downloads or auto-executes binaries; validates SemVer and HTTPS GitHub release URLs.
enum UpdateChecker {
    private static let maxResponseBytes = 512 * 1024

    static var currentAppVersion: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "1.0.0"
    }

    static func isValidRepoSlug(_ slug: String) -> Bool {
        let trimmed = slug.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: "/")
        guard parts.count == 2 else { return false }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        return parts.allSatisfy { !$0.isEmpty && $0.unicodeScalars.allSatisfy { allowed.contains($0) } }
    }

    static func checkLatestRelease(
        repoSlug: String,
        currentVersion: String = currentAppVersion,
        proxyPort: Int? = nil
    ) async throws -> ReleaseCheckResult {
        let slug = repoSlug.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidRepoSlug(slug),
              let url = URL(string: "https://api.github.com/repos/\(slug)/releases/latest") else {
            throw UpdateCheckError.invalidRepoSlug
        }

        let (data, response) = try await Diagnostics.httpRequest(
            url,
            headers: [
                "Accept": "application/vnd.github+json",
                "User-Agent": "ClaudeEnvironmentCheck/\(currentVersion)",
            ],
            proxyPort: proxyPort,
            timeout: 7
        )

        if response.statusCode == 404 {
            return ReleaseCheckResult(currentVersion: currentVersion, repoSlug: slug, status: .noReleases, checkedAt: Date())
        }
        guard response.statusCode == 200 else {
            throw UpdateCheckError.httpError(response.statusCode)
        }
        guard data.count <= maxResponseBytes else {
            throw UpdateCheckError.responseTooLarge
        }
        return try parseReleaseJSON(data, repoSlug: slug, currentVersion: currentVersion)
    }

    static func parseReleaseJSON(_ data: Data, repoSlug: String, currentVersion: String) throws -> ReleaseCheckResult {
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw UpdateCheckError.invalidPayload
        }
        let isDraft = (obj["draft"] as? Bool) ?? false
        let isPrerelease = (obj["prerelease"] as? Bool) ?? false
        if isDraft || isPrerelease {
            return ReleaseCheckResult(currentVersion: currentVersion, repoSlug: repoSlug, status: .noReleases, checkedAt: Date())
        }
        guard let tagName = obj["tag_name"] as? String,
              let latest = SemVer(tagName),
              let htmlURLStr = obj["html_url"] as? String,
              let releaseURL = URL(string: htmlURLStr),
              releaseURL.scheme == "https",
              releaseURL.host?.lowercased() == "github.com" else {
            throw UpdateCheckError.invalidPayload
        }

        let current = SemVer(currentVersion)
        let dmgAsset: String? = {
            guard let assets = obj["assets"] as? [[String: Any]] else { return nil }
            for asset in assets {
                if let name = asset["name"] as? String, name.lowercased().hasSuffix("arm64.dmg") {
                    return name
                }
            }
            return nil
        }()
        let notes = (obj["body"] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .prefix(240)
            .description

        if let current, latest > current {
            return ReleaseCheckResult(
                currentVersion: currentVersion,
                repoSlug: repoSlug,
                status: .updateAvailable(latest: latest, releaseURL: releaseURL, assetName: dmgAsset, notes: notes),
                checkedAt: Date()
            )
        }
        return ReleaseCheckResult(
            currentVersion: currentVersion,
            repoSlug: repoSlug,
            status: .upToDate,
            checkedAt: Date()
        )
    }
}
