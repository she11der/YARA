rule ELASTIC_Windows_Trojan_Doorme_246Eda61 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Doorme (Windows.Trojan.DoorMe)"
		author = "Elastic Security"
		id = "246eda61-23b5-49b8-8409-623f2722c289"
		date = "2022-12-09"
		modified = "2022-12-15"
		reference = "https://www.elastic.co/security-labs/update-to-the-REF2924-intrusion-set-and-related-campaigns"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_DoorMe.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "96b226e1dcfb8ea2155c2fa508125472c8c767569d009a881ab4c39453e4fe7f"
		logic_hash = "01240f2e23904498c34ec805cc8bc3e9ac7b76c6519685ef6b367066f1a0bc5b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "aa8c2ae2e966bf4e0c79faa90b14fd77d07b7c68076f39c56b384dada9dd0e96"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$seq_aes_crypto = { 8B 6C 24 ?? C1 E5 ?? 8B 5C 24 ?? 8D 34 9D ?? ?? ?? ?? 0F B6 04 31 32 44 24 ?? 88 04 29 8D 04 9D ?? ?? ?? ?? 0F B6 04 01 32 44 24 ?? 88 44 29 ?? 8D 04 9D ?? ?? ?? ?? 0F B6 04 01 44 30 F8 88 44 29 ?? 8D 04 9D ?? ?? ?? ?? 0F B6 04 01 44 30 E0 88 44 29 ?? 8B 74 24 ?? }
		$seq_copy_str = { 48 8B 44 24 ?? 48 89 58 ?? 48 89 F1 4C 89 F2 49 89 D8 E8 ?? ?? ?? ?? C6 04 1E ?? }
		$seq_md5 = { 89 F8 44 21 C8 44 89 C9 F7 D1 21 F1 44 01 C0 01 C8 44 8B AC 24 ?? ?? ?? ?? 8B 9C 24 ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 44 89 44 24 ?? 46 8D 04 28 41 81 C0 ?? ?? ?? ?? 4C 89 AC 24 ?? ?? ?? ?? 41 C1 C0 ?? 45 01 C8 44 89 C1 44 21 C9 44 89 C2 F7 D2 21 FA 48 89 BC 24 ?? ?? ?? ?? 8D 2C 1E 49 89 DC 01 D5 01 E9 81 C1 ?? ?? ?? ?? C1 C1 ?? 44 01 C1 89 CA 44 21 C2 89 CD F7 D5 44 21 CD 8B 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 8D 1C 07 01 EB 01 DA 81 C2 ?? ?? ?? ?? C1 C2 ?? }
		$seq_calc_key = { 31 FF 48 8D 1D ?? ?? ?? ?? 48 83 FF ?? 4C 89 F8 77 ?? 41 0F B6 34 3E 48 89 F1 48 C1 E9 ?? 44 0F B6 04 19 BA ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 83 E6 ?? 44 0F B6 04 1E BA ?? ?? ?? ?? 48 8B 4D ?? E8 ?? ?? ?? ?? 48 83 C7 ?? }
		$seq_base64 = { 8A 45 ?? 8A 4D ?? C0 E0 ?? 89 CA C0 EA ?? 80 E2 ?? 08 C2 88 55 ?? C0 E1 ?? 8A 45 ?? C0 E8 ?? 24 ?? 08 C8 88 45 ?? 41 83 C4 ?? 31 F6 44 39 E6 7D ?? 66 90 }
		$str_0 = ".?AVDoorme@@" ascii fullword

	condition:
		3 of ($seq*) or 1 of ($str*)
}