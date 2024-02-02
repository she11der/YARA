rule JPCERTCC_Poisonivy
{
	meta:
		description = "detect PoisonIvy in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "e7b27a88-490f-5f79-9e8c-65b8f7505a72"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L336-L349"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "dec7a95c877078f77cbcdcf8646680f6f1d55d438af98e519d13461a7854b095"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$a1 = { 0E 89 02 44 }
		$b1 = { AD D1 34 41 }
		$c1 = { 66 35 20 83 66 81 F3 B8 ED }

	condition:
		all of them
}