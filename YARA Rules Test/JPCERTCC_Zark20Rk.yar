rule JPCERTCC_Zark20Rk
{
	meta:
		description = "detect zark20rk(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "baf3ebfe-80dd-5601-9ba9-8866b6ab6f14"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L113-L126"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "07c5c97916bd9ec19591d90f8b7d872fca571f3479148157cf1ee9e05c272e5c"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

	strings:
		$a1 = { C7 ?? ?? 7A 61 72 6B }
		$a2 = { C7 ?? ?? 32 30 72 6B }

	condition:
		all of them
}