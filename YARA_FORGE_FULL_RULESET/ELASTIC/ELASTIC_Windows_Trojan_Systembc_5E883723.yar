rule ELASTIC_Windows_Trojan_Systembc_5E883723 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Systembc (Windows.Trojan.SystemBC)"
		author = "Elastic Security"
		id = "5e883723-7eaa-4992-91de-abb0ffbba54e"
		date = "2022-03-22"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_SystemBC.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "b432805eb6b2b58dd957481aa8a973be58915c26c04630ce395753c6a5196b14"
		logic_hash = "fde2e0b5debd4d26838fb245fdf8e5103ab5aab9feff900cbba00c1950adc61a"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "add95c1f4bb279c8b189c3d64a0c2602c73363ebfad56a4077119af148dd2d87"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "GET /tor/rendezvous2/%s HTTP/1.0" ascii fullword
		$a2 = "https://api.ipify.org/" ascii fullword
		$a3 = "KEY-----" ascii fullword
		$a4 = "Host: %s" ascii fullword
		$a5 = "BEGINDATA" ascii fullword
		$a6 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword

	condition:
		all of them
}
