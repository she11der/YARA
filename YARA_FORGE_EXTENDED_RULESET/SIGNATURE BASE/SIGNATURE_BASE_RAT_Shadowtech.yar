rule SIGNATURE_BASE_RAT_Shadowtech : FILE
{
	meta:
		description = "Detects ShadowTech RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "1fb15030-b400-5e70-b183-81e2527d5556"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/ShadowTech"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L819-L839"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
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
