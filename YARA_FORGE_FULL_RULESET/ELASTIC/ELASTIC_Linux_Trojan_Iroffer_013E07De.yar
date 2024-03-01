rule ELASTIC_Linux_Trojan_Iroffer_013E07De : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Iroffer (Linux.Trojan.Iroffer)"
		author = "Elastic Security"
		id = "013e07de-95bd-4774-a14f-0a10f911a2dd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Trojan_Iroffer.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
		logic_hash = "ce21de61f94d41aa3abb73b9391a4d9c8ddeea75f1a2b36be58111b70a9590fe"
		score = 60
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "92dde62076acec29a637b63a35f00c35f706df84d6ee9cabda0c6f63d01a13c4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 49 67 6E 6F 72 69 6E 67 20 42 61 64 20 58 44 43 43 20 4E 6F }

	condition:
		all of them
}
