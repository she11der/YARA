rule SIGNATURE_BASE_RAT_Xtreme
{
	meta:
		description = "Detects Xtreme RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "02b7bb6a-5d1e-5379-b366-868680844719"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Xtreme"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L969-L990"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4dec8de6609f8229444291a78e920ac48b9b5751dd0cad7c95bc6529d6f8c16c"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"
		ver = "2.9, 3.1, 3.2, 3.5"

	strings:
		$a = "XTREME" wide
		$b = "ServerStarted" wide
		$c = "XtremeKeylogger" wide
		$d = "x.html" wide
		$e = "Xtreme RAT" wide

	condition:
		all of them
}
