package regions

import "strings"

type SupportStatus string

const (
	Supported   SupportStatus = "supported"
	Unsupported SupportStatus = "unsupported"
	Unknown     SupportStatus = "unknown"
)

type ProcessLocale struct {
	TimeZone string `json:"timeZone"`
	Lang     string `json:"lang"`
	BCP47    string `json:"bcp47"`
}

// SupportedCodes matches Anthropic's official 185 supported countries/territories list (1:1 parity with macOS).
var SupportedCodes = map[string]bool{
	"AD": true, "AE": true, "AG": true, "AL": true, "AM": true, "AO": true, "AR": true, "AT": true, "AU": true, "AZ": true,
	"BA": true, "BB": true, "BD": true, "BE": true, "BF": true, "BG": true, "BH": true, "BI": true, "BJ": true, "BN": true,
	"BO": true, "BR": true, "BS": true, "BT": true, "BW": true, "BZ": true,
	"CA": true, "CD": true, "CF": true, "CG": true, "CH": true, "CI": true, "CL": true, "CM": true, "CO": true, "CR": true,
	"CV": true, "CY": true, "CZ": true,
	"DE": true, "DJ": true, "DK": true, "DM": true, "DO": true, "DZ": true,
	"EC": true, "EE": true, "EG": true, "ER": true, "ES": true, "ET": true,
	"FI": true, "FJ": true, "FM": true, "FR": true,
	"GA": true, "GB": true, "GD": true, "GE": true, "GH": true, "GM": true, "GN": true, "GQ": true, "GR": true, "GT": true,
	"GW": true, "GY": true,
	"HN": true, "HR": true, "HT": true, "HU": true,
	"ID": true, "IE": true, "IL": true, "IN": true, "IQ": true, "IS": true, "IT": true,
	"JM": true, "JO": true, "JP": true,
	"KE": true, "KG": true, "KH": true, "KI": true, "KM": true, "KN": true, "KR": true, "KW": true, "KZ": true,
	"LA": true, "LB": true, "LC": true, "LI": true, "LK": true, "LR": true, "LS": true, "LT": true, "LU": true, "LV": true, "LY": true,
	"MA": true, "MC": true, "MD": true, "ME": true, "MG": true, "MH": true, "MK": true, "ML": true, "MN": true, "MR": true,
	"MT": true, "MU": true, "MV": true, "MW": true, "MX": true, "MY": true, "MZ": true,
	"NA": true, "NE": true, "NG": true, "NI": true, "NL": true, "NO": true, "NP": true, "NR": true, "NZ": true,
	"OM": true,
	"PA": true, "PE": true, "PG": true, "PH": true, "PK": true, "PL": true, "PS": true, "PT": true, "PW": true, "PY": true,
	"QA": true,
	"RO": true, "RS": true, "RW": true,
	"SA": true, "SB": true, "SC": true, "SD": true, "SE": true, "SG": true, "SI": true, "SK": true, "SL": true, "SM": true,
	"SN": true, "SO": true, "SR": true, "SS": true, "ST": true, "SV": true, "SZ": true,
	"TD": true, "TG": true, "TH": true, "TJ": true, "TL": true, "TM": true, "TN": true, "TO": true, "TR": true, "TT": true,
	"TV": true, "TW": true, "TZ": true,
	"UA": true, "UG": true, "US": true, "UY": true, "UZ": true,
	"VA": true, "VC": true, "VN": true, "VU": true,
	"WS": true, "ZA": true, "ZM": true, "ZW": true,
}

var chineseNames = map[string]string{
	"US": "美国", "JP": "日本", "SG": "新加坡", "TW": "台湾", "KR": "韩国",
	"GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰", "CA": "加拿大",
	"AU": "澳大利亚", "CH": "瑞士", "SE": "瑞典", "IE": "爱尔兰", "FI": "芬兰",
	"NO": trueName("挪威"), "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度",
	"MY": "马来西亚", "TH": "泰国", "VN": "越南", "PH": "菲律宾", "ID": "印度尼西亚",
	"BR": "巴西", "MX": "墨西哥", "NZ": "新西兰", "AE": "阿联酋", "TR": "土耳其",
	"CN": "中国内地", "HK": "中国香港", "MO": "中国澳门", "RU": "俄罗斯",
	"BY": "白俄罗斯", "IR": "伊朗", "KP": "朝鲜", "SY": "叙利亚", "CU": "古巴",
}

func trueName(s string) string { return s }

func Normalize(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if len(s) != 2 {
		return ""
	}
	for i := 0; i < 2; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return ""
		}
	}
	return s
}

func Support(code string) SupportStatus {
	c := Normalize(code)
	if c == "" {
		return Unknown
	}
	if SupportedCodes[c] {
		return Supported
	}
	return Unsupported
}

func DisplayName(code string) string {
	c := Normalize(code)
	if c == "" {
		return "未知地区"
	}
	if name, ok := chineseNames[c]; ok {
		return name + " (" + c + ")"
	}
	return c
}

var defaultTZByCountry = map[string]string{
	"US": "America/New_York", "CA": "America/Toronto", "GB": "Europe/London",
	"DE": "Europe/Berlin", "FR": "Europe/Paris", "NL": "Europe/Amsterdam",
	"CH": "Europe/Zurich", "SE": "Europe/Stockholm", "IE": "Europe/Dublin",
	"JP": "Asia/Tokyo", "KR": "Asia/Seoul", "SG": "Asia/Singapore",
	"TW": "Asia/Taipei", "AU": "Australia/Sydney", "NZ": "Pacific/Auckland",
	"IN": "Asia/Kolkata", "MY": "Asia/Kuala_Lumpur", "TH": "Asia/Bangkok",
	"VN": "Asia/Ho_Chi_Minh", "PH": "Asia/Manila", "ID": "Asia/Jakarta",
	"BR": "America/Sao_Paulo", "MX": "America/Mexico_City", "AE": "Asia/Dubai",
	"TR": "Europe/Istanbul", "ES": "Europe/Madrid", "IT": "Europe/Rome",
	"PL": "Europe/Warsaw", "FI": "Europe/Helsinki", "NO": "Europe/Oslo",
}

var defaultLangByCountry = map[string]string{
	"US": "en_US.UTF-8", "CA": "en_CA.UTF-8", "GB": "en_GB.UTF-8",
	"AU": "en_AU.UTF-8", "NZ": "en_NZ.UTF-8", "SG": "en_SG.UTF-8",
	"IE": "en_IE.UTF-8", "JP": "ja_JP.UTF-8", "KR": "ko_KR.UTF-8",
	"TW": "zh_TW.UTF-8", "DE": "de_DE.UTF-8", "CH": "de_CH.UTF-8",
	"FR": "fr_FR.UTF-8", "NL": "nl_NL.UTF-8", "ES": "es_ES.UTF-8",
	"IT": "it_IT.UTF-8", "SE": "sv_SE.UTF-8", "PL": "pl_PL.UTF-8",
	"BR": "pt_BR.UTF-8", "MX": "es_MX.UTF-8", "TR": "tr_TR.UTF-8",
}

func RecommendedProcessLocale(countryCode, geoTimeZone string) ProcessLocale {
	c := Normalize(countryCode)
	tz := strings.TrimSpace(geoTimeZone)
	if tz == "" {
		if v, ok := defaultTZByCountry[c]; ok {
			tz = v
		} else {
			tz = "UTC"
		}
	}
	lang := "en_US.UTF-8"
	if v, ok := defaultLangByCountry[c]; ok {
		lang = v
	}
	bcp47 := strings.ReplaceAll(strings.Split(lang, ".")[0], "_", "-")
	return ProcessLocale{TimeZone: tz, Lang: lang, BCP47: bcp47}
}

func AcceptLanguages(bcp47 string) string {
	parts := strings.Split(bcp47, "-")
	if len(parts) >= 2 && !strings.EqualFold(parts[0], bcp47) {
		return bcp47 + "," + parts[0]
	}
	return bcp47
}
