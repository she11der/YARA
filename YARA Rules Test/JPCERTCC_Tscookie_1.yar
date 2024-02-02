rule JPCERTCC_Tscookie_1
{
	meta:
		description = "detect TSCookie in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "5407a5c9-2fc5-5b9b-977f-81384a343d15"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L8-L21"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "71e51ceb51cff25abefd698ce33f32388cc28ad5936f30fbbb9925d9af79ad85"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

	strings:
		$v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
		$b1 = { 68 D4 08 00 00 }

	condition:
		all of them
}