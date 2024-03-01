rule ELASTIC_Windows_Hacktool_Sharpchromium_41Ce5080 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpchromium (Windows.Hacktool.SharpChromium)"
		author = "Elastic Security"
		id = "41ce5080-7d84-4a56-8de8-86959eb92057"
		date = "2022-11-20"
		modified = "2023-01-11"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Hacktool_SharpChromium.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "9dd65aa53728d51f0f3b9aaf51a24f8a2c3f84b4a4024245575975cf9ad7f2e5"
		logic_hash = "50972a6e6af1d7076243320fb6559193e0c46ac1300aa62d12390fdeb2fffdcd"
		score = 75
		quality = 48
		tags = "FILE, MEMORY"
		fingerprint = "b6695ded1a6f647812c7f355e089a2ed7209ac59f51a97d8f6b1897bb1e7d9ad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "F1653F20-D47D-4F29-8C55-3C835542AF5F" ascii wide nocase
		$print_str0 = "[X] Exception occurred while writing cookies to file: {0}" ascii wide fullword
		$print_str1 = "[*] All cookies written to {0}" ascii wide fullword
		$print_str2 = "\\{0}-cookies.json" ascii wide fullword
		$print_str3 = "[*] {0} {1} extraction." ascii wide fullword

	condition:
		$guid or all of ($print_str*)
}
