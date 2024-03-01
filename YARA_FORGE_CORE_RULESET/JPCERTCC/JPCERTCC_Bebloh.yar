rule JPCERTCC_Bebloh
{
	meta:
		description = "detect Bebloh(a.k.a. URLZone) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "7c3decb2-9cb5-5569-bab2-982c769ee233"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L290-L304"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "22b8ae9d40d34f83d8cc6c2dab56a866c8de8c9cc38b5da962c7071302f91f03"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$crc32f = { b8 EE 56 0b ca }
		$dga = "qwertyuiopasdfghjklzxcvbnm123945678"
		$post1 = "&vcmd="
		$post2 = "?tver="

	condition:
		all of them
}
