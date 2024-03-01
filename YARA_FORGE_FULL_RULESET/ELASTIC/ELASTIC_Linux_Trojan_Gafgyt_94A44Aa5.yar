rule ELASTIC_Linux_Trojan_Gafgyt_94A44Aa5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "94a44aa5-6c8b-40b9-8aac-d18cf4a76a19"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Trojan_Gafgyt.yar#L296-L314"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "a7694202f9c32a9d73a571a30a9e4a431d5dfd7032a500084756ba9a48055dba"
		logic_hash = "deb46c2960dc4868b7bac1255d8753895950bc066dec03674a714860ff72ef2c"
		score = 60
		quality = 45
		tags = "FILE, MEMORY"
		fingerprint = "daf7e0382dd4a566eb5a4aac8c5d9defd208f332d8e327637d47b50b9ef271f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 83 F8 FF 0F 45 C2 48 8B 4C 24 08 64 48 33 0C 25 28 00 }

	condition:
		all of them
}
