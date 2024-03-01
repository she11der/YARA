rule SIGNATURE_BASE_RAT_Bandook
{
	meta:
		description = "Detects Bandook RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "79fb99d8-bd56-5986-9917-e119b51b8303"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/bandook"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L95-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fe658e0990f0d456b1a8f5acea62a3b80bdd4a9bc0eedfe2e1092ea60b4fca2e"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "aaaaaa1|"
		$b = "aaaaaa2|"
		$c = "aaaaaa3|"
		$d = "aaaaaa4|"
		$e = "aaaaaa5|"
		$f = "%s%d.exe"
		$g = "astalavista"
		$h = "givemecache"
		$i = "%s\\system32\\drivers\\blogs\\*"
		$j = "bndk13me"

	condition:
		all of them
}
