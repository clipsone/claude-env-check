import Foundation

enum RegionSupport: String, Codable, Equatable, Sendable {
    case supported
    case unsupported
    case unknown
}

enum ClaudeRegions {
    static let policyURL = "https://www.anthropic.com/legal/supported-regions"
    static let retrievedAt = "2026-11-07"

    /// Official Anthropic Supported Regions (ISO 3166-1 alpha-2, 185 codes).
    static let supportedCodes: Set<String> = [
        "AD", "AE", "AG", "AL", "AM", "AO", "AR", "AT", "AU", "AZ",
        "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BN",
        "BO", "BR", "BS", "BT", "BW", "BZ", "CA", "CD", "CF", "CG",
        "CH", "CI", "CL", "CM", "CO", "CR", "CV", "CY", "CZ", "DE",
        "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "ER", "ES",
        "ET", "FI", "FJ", "FM", "FR", "GA", "GB", "GD", "GE", "GH",
        "GM", "GN", "GQ", "GR", "GT", "GW", "GY", "HN", "HR", "HT",
        "HU", "ID", "IE", "IL", "IN", "IQ", "IS", "IT", "JM", "JO",
        "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KZ",
        "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV",
        "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK", "ML", "MN",
        "MR", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NE",
        "NG", "NI", "NL", "NO", "NP", "NR", "NZ", "OM", "PA", "PE",
        "PG", "PH", "PK", "PL", "PS", "PT", "PW", "PY", "QA", "RO",
        "RS", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SI", "SK",
        "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SZ", "TD",
        "TG", "TH", "TJ", "TL", "TM", "TN", "TO", "TR", "TT", "TV",
        "TW", "TZ", "UA", "UG", "US", "UY", "UZ", "VA", "VC", "VN",
        "VU", "WS", "ZA", "ZM", "ZW",
    ]

    private static let zhLocale = Locale(identifier: "zh_Hans_CN")

    private static let displayOverrides: [String: String] = [
        "CN": "中国大陆",
        "HK": "中国香港",
        "MO": "中国澳门",
        "TW": "中国台湾",
        "US": "美国",
        "GB": "英国",
        "JP": "日本",
        "KR": "韩国",
        "SG": "新加坡",
        "DE": "德国",
        "FR": "法国",
        "NL": "荷兰",
        "CA": "加拿大",
        "AU": "澳大利亚",
        "RU": "俄罗斯",
    ]

    static func normalize(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let code = raw.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard code.count == 2, code.allSatisfy({ $0.isASCII && $0.isLetter }) else {
            return nil
        }
        return code
    }

    static func support(for countryCode: String?) -> RegionSupport {
        guard let code = normalize(countryCode) else { return .unknown }
        return supportedCodes.contains(code) ? .supported : .unsupported
    }

    static func displayName(for countryCode: String?) -> String {
        guard let code = normalize(countryCode) else { return "未知地区" }
        if let override = displayOverrides[code] {
            return "\(override) (\(code))"
        }
        if let localized = zhLocale.localizedString(forRegionCode: code), !localized.isEmpty {
            return "\(localized) (\(code))"
        }
        return code
    }

    static func shortName(for countryCode: String?) -> String {
        guard let code = normalize(countryCode) else { return "未知" }
        if let override = displayOverrides[code] {
            return override
        }
        return zhLocale.localizedString(forRegionCode: code) ?? code
    }

    struct ProcessLocaleProfile: Equatable, Sendable {
        let timeZone: String
        let lang: String
    }

    private static let countryDefaults: [String: (tz: String, lang: String)] = [
        "US": ("America/Los_Angeles", "en_US.UTF-8"),
        "CA": ("America/Toronto", "en_CA.UTF-8"),
        "GB": ("Europe/London", "en_GB.UTF-8"),
        "JP": ("Asia/Tokyo", "ja_JP.UTF-8"),
        "KR": ("Asia/Seoul", "ko_KR.UTF-8"),
        "SG": ("Asia/Singapore", "en_SG.UTF-8"),
        "TW": ("Asia/Taipei", "zh_TW.UTF-8"),
        "DE": ("Europe/Berlin", "de_DE.UTF-8"),
        "FR": ("Europe/Paris", "fr_FR.UTF-8"),
        "NL": ("Europe/Amsterdam", "nl_NL.UTF-8"),
        "AU": ("Australia/Sydney", "en_AU.UTF-8"),
        "NZ": ("Pacific/Auckland", "en_NZ.UTF-8"),
        "IE": ("Europe/Dublin", "en_IE.UTF-8"),
        "CH": ("Europe/Zurich", "de_CH.UTF-8"),
        "SE": ("Europe/Stockholm", "sv_SE.UTF-8"),
        "NO": ("Europe/Oslo", "nb_NO.UTF-8"),
        "FI": ("Europe/Helsinki", "fi_FI.UTF-8"),
        "ES": ("Europe/Madrid", "es_ES.UTF-8"),
        "IT": ("Europe/Rome", "it_IT.UTF-8"),
        "PL": ("Europe/Warsaw", "pl_PL.UTF-8"),
        "BR": ("America/Sao_Paulo", "pt_BR.UTF-8"),
        "MX": ("America/Mexico_City", "es_MX.UTF-8"),
        "IN": ("Asia/Kolkata", "en_IN.UTF-8"),
        "MY": ("Asia/Kuala_Lumpur", "en_MY.UTF-8"),
        "TH": ("Asia/Bangkok", "th_TH.UTF-8"),
        "VN": ("Asia/Ho_Chi_Minh", "vi_VN.UTF-8"),
        "ID": ("Asia/Jakarta", "id_ID.UTF-8"),
        "PH": ("Asia/Manila", "en_PH.UTF-8"),
        "AE": ("Asia/Dubai", "en_AE.UTF-8"),
        "IL": ("Asia/Jerusalem", "he_IL.UTF-8"),
        "ZA": ("Africa/Johannesburg", "en_ZA.UTF-8"),
    ]

    /// Produces a safe process-level TZ/LANG pair for any of the 185 Anthropic-supported regions
    /// without mutating macOS global system timezone.
    static func recommendedProcessLocale(countryCode: String?, geoTimeZone: String?) -> ProcessLocaleProfile {
        let code = normalize(countryCode)
        let preset = code.flatMap { countryDefaults[$0] }
        let resolvedTZ: String
        if let geoTZ = geoTimeZone?.trimmingCharacters(in: .whitespacesAndNewlines),
           !geoTZ.isEmpty,
           TimeZone(identifier: geoTZ) != nil {
            resolvedTZ = geoTZ
        } else {
            resolvedTZ = preset?.tz ?? "UTC"
        }
        let resolvedLang = preset?.lang ?? "en_US.UTF-8"
        return ProcessLocaleProfile(timeZone: resolvedTZ, lang: resolvedLang)
    }
}
