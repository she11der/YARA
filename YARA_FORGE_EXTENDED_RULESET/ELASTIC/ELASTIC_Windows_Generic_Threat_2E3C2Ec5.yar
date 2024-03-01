rule ELASTIC_Windows_Generic_Threat_2E3C2Ec5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "2e3c2ec5-4a95-4fea-90d0-8bf7c9cb2b27"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Generic_Threat.yar#L1951-L1969"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "91755a6831a4aa2d66fea9c3d6203b0ed3f1f58e0f4e1d1550aba4fe18895695"
		logic_hash = "51b76a28c1ca4485c73031259f6c40a5e213287acc9b09478dca68c6e258270e"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "7900635bfb947487995d3d27fd56c47d1b4549bce6216cffc04c000811d6f4ae"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 57 69 6E 64 6F 77 55 70 64 61 74 65 73 69 7A 65 5F 69 6E 63 72 65 6D 65 6E 74 50 6F 69 73 6F 6E 45 72 72 6F 72 57 69 6E 64 6F 77 }

	condition:
		all of them
}
