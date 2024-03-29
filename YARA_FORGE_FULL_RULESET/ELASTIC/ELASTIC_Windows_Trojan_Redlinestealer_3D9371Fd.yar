rule ELASTIC_Windows_Trojan_Redlinestealer_3D9371Fd : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "3d9371fd-c094-40fc-baf8-f0e9e9a54ff9"
		date = "2022-02-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_RedLineStealer.yar#L78-L102"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "0ec522dfd9307772bf8b600a8b91fd6facd0bf4090c2b386afd20e955b25206a"
		logic_hash = "1c8a64ce7615f502602ab960638dd55f4deaeea3b49d894274d64d4d0b6a1d10"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "2d7ff7894b267ba37a2d376b022bae45c4948ef3a70b1af986e7492949b5ae23"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "get_encrypted_key" ascii fullword
		$a2 = "get_PassedPaths" ascii fullword
		$a3 = "ChromeGetLocalName" ascii fullword
		$a4 = "GetBrowsers" ascii fullword
		$a5 = "Software\\Valve\\SteamLogin Data" wide fullword
		$a6 = "%appdata%\\" wide fullword
		$a7 = "ScanPasswords" ascii fullword

	condition:
		all of them
}
