rule JPCERTCC_Remcos_1
{
	meta:
		description = "detect Remcos in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "4a27a16a-2669-5009-bc82-082ec0c9b2c1"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L480-L493"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "1b4b9f7a88f33faeda71ea9a354eeccba8889800f48a6280c4ec533bb1b3ef3d"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "7d5efb7e8b8947e5fe1fa12843a2faa0ebdfd7137582e5925a0b9c6a9350b0a5"

	strings:
		$remcos = "Remcos" ascii fullword
		$url1 = "Breaking-Security.Net" ascii fullword
		$url2 = "BreakingSecurity.Net" ascii fullword
		$resource = "SETTINGS" ascii wide fullword

	condition:
		1 of ($url*) and $remcos and $resource
}