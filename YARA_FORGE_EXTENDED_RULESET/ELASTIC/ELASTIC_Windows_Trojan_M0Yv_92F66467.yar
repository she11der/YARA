rule ELASTIC_Windows_Trojan_M0Yv_92F66467 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan M0Yv (Windows.Trojan.M0yv)"
		author = "Elastic Security"
		id = "92f66467-89fd-4501-b045-3c6aed6c82f9"
		date = "2023-05-03"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_M0yv.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "0004d22dd18c0239b722c085101c0a32b967159e2066a0b7b9104bb43f5cdea0"
		logic_hash = "a47b20679aee9559213de22783cfbc55c6091785e4dc288349963e863b78cf41"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "2afebc9478fbad18b74748794773cae9be3a4eac599d657bab5a7f8de331ba41"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 54 65 7D 41 69 6E 63 5D 6A 68 6D }
		$a2 = { 4E 73 4D 62 62 77 61 6E 66 77 58 72 61 72 64 6C 7D }
		$a3 = { 40 65 7D 41 69 6E 63 48 77 71 7A 69 66 74 75 67 7A 55 }

	condition:
		all of them
}
