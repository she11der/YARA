rule ELASTIC_Linux_Ransomware_Blacksuit_9F53E7E5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Blacksuit (Linux.Ransomware.BlackSuit)"
		author = "Elastic Security"
		id = "9f53e7e5-7177-4e17-ac12-9214c4deddf2"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Linux_Ransomware_BlackSuit.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
		logic_hash = "121e0139385cfef5dff394c4ea36d950314b00c6d7021cf2ca667ee942e74763"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "34355cb1731fe6c8fa684a484943127f8fdf3814d45025e29bdf25a08b4890fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "esxcli vm process list > list_" fullword
		$a2 = "Drop readme failed: %s(%d)" fullword
		$a3 = "README.BlackSuit.txt" fullword

	condition:
		2 of them
}
