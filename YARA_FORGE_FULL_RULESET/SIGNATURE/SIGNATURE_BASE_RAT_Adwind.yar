rule SIGNATURE_BASE_RAT_Adwind
{
	meta:
		description = "Detects Adwind RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "95681c07-0e9c-5688-a8a0-899617521c7b"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/adWind"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L992-L1011"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "11167b927fa06324950753c6ec8f28058f2aa66fb4ecdf66a21de11a8db190b8"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$meta = "META-INF"
		$conf = "config.xml"
		$a = "Adwind.class"
		$b = "Principal.adwind"

	condition:
		all of them
}
