rule SIGNATURE_BASE_RAT_Shadowtech : FILE
{
	meta:
		description = "Detects ShadowTech RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "1fb15030-b400-5e70-b183-81e2527d5556"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/ShadowTech"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L819-L839"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8ab024ae5ca62de30daf4392db5241220fcdb9b419bad555a996729aed9fa45d"
		score = 75
		quality = 83
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "ShadowTech" nocase
		$b = "DownloadContainer"
		$c = "MySettings"
		$d = "System.Configuration"
		$newline = "#-@NewLine@-#" wide
		$split = "pSIL" wide
		$key = "ESIL" wide

	condition:
		4 of them
}
