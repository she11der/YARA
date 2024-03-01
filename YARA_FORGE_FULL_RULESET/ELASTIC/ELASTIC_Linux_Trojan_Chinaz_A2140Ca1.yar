rule ELASTIC_Linux_Trojan_Chinaz_A2140Ca1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Chinaz (Linux.Trojan.Chinaz)"
		author = "Elastic Security"
		id = "a2140ca1-0a72-4dcb-bf7c-2f51e84a996b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Trojan_Chinaz.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "7c44c2ca77ef7a62446f6266a757817a6c9af5e010a219a43a1905e2bc5725b0"
		logic_hash = "c9c63114e45b45b1c243af1f719cddc838a06a1f35d65dca6a2fb5574047eff0"
		score = 60
		quality = 45
		tags = "FILE, MEMORY"
		fingerprint = "ac620f3617ea448b2ad62f06490c37200fa0af8a6fe75a6a2a294a7b5b4a634a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 53 8B 74 24 0C 8B 5C 24 10 8D 74 26 00 89 C2 89 C1 C1 FA 03 83 }

	condition:
		all of them
}
