rule JPCERTCC_Formbook_1
{
	meta:
		description = "detect Formbook in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "71291f9b-eb8e-55e5-a499-df54c35efdbf"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L384-L397"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "62bd3717af8970f67f28d923ce2483ff55a5ef4585a183d4d510e3a2c45fcc8c"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$sqlite3step = { 68 34 1c 7b e1 }
		$sqlite3text = { 68 38 2a 90 c5 }
		$sqlite3blob = { 68 53 d8 7f 8c }

	condition:
		all of them
}