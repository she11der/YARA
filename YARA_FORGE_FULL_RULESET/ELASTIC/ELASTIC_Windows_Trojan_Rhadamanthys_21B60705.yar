rule ELASTIC_Windows_Trojan_Rhadamanthys_21B60705 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Rhadamanthys (Windows.Trojan.Rhadamanthys)"
		author = "Elastic Security"
		id = "21b60705-9696-43ba-a820-d8ab9c34cca2"
		date = "2023-03-19"
		modified = "2023-04-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Rhadamanthys.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "3ba97c51ba503fa4bdcfd5580c75436bc88794b4ae883afa1d92bb0b2a0f5efe"
		logic_hash = "ef3f60689d72553111b42b27e0a1a0316288ae07fbfaf159eea8c76380d528fa"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "8a756bf4a8c9402072531aca2c29a382881c1808a790432ccac2240b35c09383"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Session\\%u\\MSCTF.Asm.{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide fullword
		$a2 = "MSCTF.Asm.{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide fullword
		$a3 = " \"%s\",Options_RunDLL %s" wide fullword
		$a4 = "%%TEMP%%\\vcredist_%05x.dll" wide fullword
		$a5 = "%%APPDATA%%\\vcredist_%05x.dll" wide fullword
		$a6 = "TEQUILABOOMBOOM" wide fullword
		$a7 = "%Systemroot%\\system32\\rundll32.exe" wide fullword

	condition:
		4 of them
}
