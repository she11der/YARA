rule JPCERTCC_Njrat
{
	meta:
		description = "detect njRAT in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "96b35796-3e1d-5721-998a-e678612e4de7"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L444-L456"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "398614ff5ea37dfaf6c36f60702cb7cdfe66b4569c698e9c3ea29563e4031856"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "d5f63213ce11798879520b0e9b0d1b68d55f7727758ec8c120e370699a41379d"

	strings:
		$reg = "SEE_MASK_NOZONECHECKS" wide fullword
		$msg = "Execute ERROR" wide fullword
		$ping = "cmd.exe /c ping 0 -n 2 & del" wide fullword

	condition:
		all of them
}