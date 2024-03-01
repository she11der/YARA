rule JPCERTCC_Lavender
{
	meta:
		description = "detect Lavender(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "8c30ae73-161f-5117-a1f9-fad0bd5278de"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L84-L97"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "bf64f927e2c8e9be0f11497f94357de8e3fadcf09ba224d6fec92841c89c1dc5"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

	strings:
		$a1 = { C7 ?? ?? 4C 41 56 45 }
		$a2 = { C7 ?? ?? 4E 44 45 52 }

	condition:
		all of them
}
