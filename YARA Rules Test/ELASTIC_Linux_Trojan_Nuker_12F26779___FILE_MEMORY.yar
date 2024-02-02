rule ELASTIC_Linux_Trojan_Nuker_12F26779___FILE_MEMORY
{
	meta:
		description = "Detects Linux Trojan Nuker (Linux.Trojan.Nuker)"
		author = "Elastic Security"
		id = "12f26779-bda5-45b1-925f-75c620d7d840"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Linux_Trojan_Nuker.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "440105a62c75dea5575a1660fe217c9104dc19fb5a9238707fe40803715392bf"
		logic_hash = "8bafbc2792bd4cacd309efd72d2d8787342685d66785ea41cb57c91519a3c545"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9093a96321ad912f2bb953cce460d0945c1c4e5aacd8431f343498203b85bb9b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C4 18 89 45 D8 83 7D D8 FF 75 17 68 ?? ?? 04 08 }

	condition:
		all of them
}