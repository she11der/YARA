rule SIGNATURE_BASE_RAT_Pythorat
{
	meta:
		description = "Detects Python RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "fc98c513-1abf-5331-b351-f6182e5b19c5"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/PythoRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L728-L751"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8edcfb8f234ff225537d19343c75788ec2a25940e80042751eea3280a967e166"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "TKeylogger"
		$b = "uFileTransfer"
		$c = "TTDownload"
		$d = "SETTINGS"
		$e = "Unknown" wide
		$f = "#@#@#"
		$g = "PluginData"
		$i = "OnPluginMessage"

	condition:
		all of them
}
