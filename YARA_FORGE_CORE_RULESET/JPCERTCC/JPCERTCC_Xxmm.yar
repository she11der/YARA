rule JPCERTCC_Xxmm
{
	meta:
		description = "detect xxmm in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "be459cbf-84a1-539e-b0b5-b7a00b6d278d"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L306-L319"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "4a860ac3efb97ce03fa906c2d0e7cd08654f6e82531d9449af7891be83a036d5"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "setupParameter:"
		$v2 = "loaderParameter:"
		$v3 = "parameter:"

	condition:
		all of them
}
