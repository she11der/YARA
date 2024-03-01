rule ELASTIC_Windows_Generic_Threat_B2A054F8 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "b2a054f8-160f-4932-b5fe-c7d78a1f9b74"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Generic_Threat.yar#L1075-L1095"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "63d2478a5db820731a48a7ad5a20d7a4deca35c6b865a17de86248bef7a64da7"
		logic_hash = "f64b1666f78646322a4c37dc887d8fcfdb275b0bca812e360579cefd9e323c02"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "09f1724963bfdde810b61d80049def388c89f6a21195e90a869bb22d19d074de"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 7E 38 7E 40 7E 44 48 4C 2A 7E 7E 58 5D 5C }
		$a2 = { 39 7B 34 74 26 39 3A 62 3A 66 25 6A }
		$a3 = { 5B 50 44 7E 66 7E 71 7E 77 7E 7C 7E }

	condition:
		all of them
}
