rule ELASTIC_Windows_Trojan_Qbot_92C67A6D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Qbot (Windows.Trojan.Qbot)"
		author = "Elastic Security"
		id = "92c67a6d-9290-4cd9-8123-7dace2cf333d"
		date = "2021-02-16"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_Trojan_Qbot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "636e2904276fe33e10cce5a562ded451665b82b24c852cbdb9882f7a54443e02"
		logic_hash = "c3466d74beaffecb8e31f2565bcb1700eb4ad0949b76e951ea51da925ba844f0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4719993107243a22552b65e6ec8dc850842124b0b9919a6ecaeb26377a1a5ebd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 33 C0 59 85 F6 74 2D 83 66 0C 00 40 89 06 6A 20 89 46 04 C7 46 08 08 00 }

	condition:
		all of them
}
