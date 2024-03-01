rule JPCERTCC_Lokibot
{
	meta:
		description = "detect Lokibot in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "12e8469b-83e9-5f93-a543-1c2efb4d303a"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L274-L288"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "3d2db6acb565d705ba26acb7f75be24096ab619a03726f4898391bfe5944bc46"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "6f12da360ee637a8eb075fb314e002e3833b52b155ad550811ee698b49f37e8c"

	strings:
		$des3 = { 68 03 66 00 00 }
		$param = "MAC=%02X%02X%02XINSTALL=%08X%08X"
		$string = { 2d 00 75 00 00 00 46 75 63 6b 61 76 2e 72 75 00 00}

	condition:
		all of them
}
