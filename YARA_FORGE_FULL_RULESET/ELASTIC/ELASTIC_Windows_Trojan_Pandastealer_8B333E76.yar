rule ELASTIC_Windows_Trojan_Pandastealer_8B333E76 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Pandastealer (Windows.Trojan.Pandastealer)"
		author = "Elastic Security"
		id = "8b333e76-f723-4093-ad72-2f5d42aaa9c9"
		date = "2021-09-02"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Pandastealer.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "ec346bd56be375b695b4bc76720959fa07d1357ffc3783eb61de9b8d91b3d935"
		logic_hash = "5878799338fc18bac0f946faeadd59c921dee32c9391fc12d22c72c0cd6733a8"
		score = 75
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "873af8643b7f08b159867c3556654a5719801aa82e1a1f6402029afad8c01487"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "] - [user: " ascii fullword
		$a2 = "[-] data unpacked failed" ascii fullword
		$a3 = "[+] data unpacked" ascii fullword
		$a4 = "\\history\\" ascii fullword
		$a5 = "PlayerName" ascii fullword

	condition:
		all of them
}
