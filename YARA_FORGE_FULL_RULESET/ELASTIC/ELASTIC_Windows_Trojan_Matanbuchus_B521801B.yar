rule ELASTIC_Windows_Trojan_Matanbuchus_B521801B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Matanbuchus (Windows.Trojan.Matanbuchus)"
		author = "Elastic Security"
		id = "b521801b-5623-4bfe-9a9d-9e16afa63c63"
		date = "2022-03-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Matanbuchus.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
		logic_hash = "609a0941b118d737124a5cd9c98c007e21557a239cfa3cf97cd3b4348c934f03"
		score = 75
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "7792cffc82678bb05ba1aa315011317611eb0bf962665e0657a7db2ce95f81b4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%PROCESSOR_ARCHITECTURE%" ascii fullword
		$a2 = "%PROCESSOR_REVISION%\\" ascii fullword
		$a3 = "%LOCALAPPDATA%\\" ascii fullword
		$a4 = "\"C:\\Windows\\system32\\schtasks.exe\" /Create /SC MINUTE /MO 1 /TN" ascii fullword

	condition:
		all of them
}
