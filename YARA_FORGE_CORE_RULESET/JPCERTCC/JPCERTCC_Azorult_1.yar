rule JPCERTCC_Azorult_1
{
	meta:
		description = "detect Azorult in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "c73a007c-4d5f-5504-9635-9bffe1282aef"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L321-L334"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "158d65dcd8f3ce8fe4ab2d9bcc97edf585c1d665cc54e1e4969ef83c8103a149"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"
		$v2 = "http://ip-api.com/json"
		$v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 }

	condition:
		all of them
}
