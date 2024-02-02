rule JPCERTCC_Armadill
{
	meta:
		description = "detect Armadill(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "0e6fb091-5c26-5419-ac99-5ddc9db29fc0"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L99-L111"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "a76d434469a45e1c48b8ec3dc9622017c78ea52824006ddfcf3c368fbda7c912"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$a1 = { C7 ?? ?? 41 72 6D 61 }
		$a2 = { C7 ?? ?? 64 69 6C 6C }

	condition:
		all of them
}