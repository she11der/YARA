rule JPCERTCC_Nanocore
{
	meta:
		description = "detect Nanocore in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "0b12ad94-99c2-5d48-a860-ff75b82971af"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L369-L382"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "471dcda6f5fb9c30e3a1df7171fdba889114d54166d038d18c7910e2765d5250"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "NanoCore Client"
		$v2 = "PluginCommand"
		$v3 = "CommandType"

	condition:
		all of them
}
