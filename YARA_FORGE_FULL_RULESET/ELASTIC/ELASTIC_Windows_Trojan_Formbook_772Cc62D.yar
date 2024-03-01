rule ELASTIC_Windows_Trojan_Formbook_772Cc62D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Formbook (Windows.Trojan.Formbook)"
		author = "Elastic Security"
		id = "772cc62d-345c-42d8-97ab-f67e447ddca4"
		date = "2022-05-23"
		modified = "2022-07-18"
		reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Formbook.yar#L25-L46"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "db9ab8df029856fc1c210499ed8e1b92c9722f7aa2264363670c47b51ec8fa83"
		score = 75
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "3d732c989df085aefa1a93b38a3c078f9f0c3ee214292f6c1e31a9fc1c9ae50e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
		$a2 = "signin"
		$a3 = "persistent"
		$r1 = /.\:\\Users\\[^\\]{1,50}\\AppData\\Roaming\\[a-zA-Z0-9]{8}\\[a-zA-Z0-9]{3}log\.ini/ wide

	condition:
		2 of ($a*) and $r1
}
