rule SIGNATURE_BASE_RAT_Luxnet
{
	meta:
		description = "Detects LuxNet RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "277db509-5ba0-5d1b-b17a-d5914f1f1650"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/LuxNet"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L495-L516"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "55d872e2e30f6d55a6f91750bbb52675042e4673d712a4f2417af43b0f2c4fb9"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "GetHashCode"
		$b = "Activator"
		$c = "WebClient"
		$d = "op_Equality"
		$e = "dickcursor.cur" wide
		$f = "{0}|{1}|{2}" wide

	condition:
		all of them
}
