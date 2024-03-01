rule ELASTIC_Linux_Trojan_Iroffer_53692410 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Iroffer (Linux.Trojan.Iroffer)"
		author = "Elastic Security"
		id = "53692410-4213-4550-890e-4c62867937bc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Trojan_Iroffer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
		logic_hash = "b8aa25fbde4d9ca36656f583e7601118a06e57703862c8b28b273881eef504fe"
		score = 60
		quality = 23
		tags = "FILE, MEMORY"
		fingerprint = "f070ee35ad42d9d30021cc2796cfd2859007201c638f98f42fdbec25c53194fb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 69 6E 67 20 55 6E 6B 6E 6F 77 6E 20 4D 73 67 6C 6F 67 20 54 61 67 }

	condition:
		all of them
}
