rule ELASTIC_Linux_Trojan_Pidief_635667D1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Pidief (Linux.Trojan.Pidief)"
		author = "Elastic Security"
		id = "635667d1-4b51-4e18-9e6b-5873194ce4f1"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Trojan_Pidief.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "e27ad676ae12188de7a04a3781aa487c11bab01d7848705bac5010d2735b19cf"
		logic_hash = "84abcc9ee40ceb6fa75b03ea6f0ece72342df7610939fb04dfa29de168818a96"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "29e1795f941990ca18fbe61154d3cfe23d43d13af298e763cd40fb9c40d7204e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 06 4C 89 F7 FF 50 10 48 8B 45 00 48 89 EF FF 50 10 85 DB 75 15 4D }

	condition:
		all of them
}
