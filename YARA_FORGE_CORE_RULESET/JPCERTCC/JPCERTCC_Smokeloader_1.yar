rule JPCERTCC_Smokeloader_1
{
	meta:
		description = "detect SmokeLoader in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "19666821-1fe9-50e7-958e-22f2260099aa"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://www.cert.pl/en/news/single/dissecting-smoke-loader/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L178-L191"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "11b7a297d3dcacba57de9b04a6d126970c2be9d5551f7976ac8129b0afbc9bfd"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$a1 = { B8 25 30 38 58 }
		$b1 = { 81 3D ?? ?? ?? ?? 25 00 41 00 }
		$c1 = { C7 ?? ?? ?? 25 73 25 73 }

	condition:
		$a1 and $b1 and $c1
}
