rule ELASTIC_Windows_Trojan_Icedid_B8C59889 : FILE MEMORY
{
	meta:
		description = "IcedID fork init loader"
		author = "Elastic Security"
		id = "b8c59889-2cc6-49c6-a81a-4bc36f3b1f6f"
		date = "2023-05-05"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_IcedID.yar#L325-L349"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "a63d08cd53053bfda17b8707ab3a94cf3d6021097335dc40d5d211fb9faed045"
		logic_hash = "08c6c604d1791c35a8494e5ec8a96e8c5dd2ca3d6c57971da20057ce8960fa1d"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "2f15ed0bc186b83a298eb51b43f10aa46ce6654ea9312a9529d36fc4cff05d4c"
		threat_name = "Windows.Trojan.IcedID"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" wide fullword
		$a2 = "\\1.bin" wide fullword
		$a3 = "c:\\ProgramData" wide fullword
		$a4 = "Loader.dll" ascii fullword
		$seq_crypto = { 83 E1 03 83 E0 03 48 8D 14 8A 41 8B 0C 80 4D 8D 04 80 41 0F B6 00 83 E1 07 02 02 41 32 04 29 41 88 04 19 49 FF C1 8B 02 }

	condition:
		4 of ($a*) or 1 of ($seq*)
}
