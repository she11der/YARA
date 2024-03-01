rule ELASTIC_Windows_Trojan_Generic_Eb47E754 : ref1296 FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "eb47e754-9b4d-45e7-b76c-027d03326c6c"
		date = "2022-02-03"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_Generic.yar#L45-L65"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		logic_hash = "1d96e813ed0261bd0d7caca2803ed8d5fe4d77ea00efc9130eef86aa872c4656"
		score = 75
		quality = 67
		tags = "FILE, MEMORY"
		fingerprint = "b71d13a34e5f791612ed414b8b0e993b1f476a8398a1b0be39046914ac5ac21d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 41 20 61 74 20 4C 20 25 64 }
		$a2 = { 74 63 70 69 70 5F 74 68 72 65 61 64 }
		$a3 = { 32 30 38 2E 36 37 2E 32 32 32 2E 32 32 32 }
		$a4 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 37 2E 30 2E 32 39 38 37 2E 31 33 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }

	condition:
		3 of them
}
