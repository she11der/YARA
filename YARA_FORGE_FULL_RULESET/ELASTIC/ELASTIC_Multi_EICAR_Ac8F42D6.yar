rule ELASTIC_Multi_EICAR_Ac8F42D6 : FILE MEMORY
{
	meta:
		description = "Detects Multi Eicar Not A Virus (Multi.EICAR.Not-a-virus)"
		author = "Elastic Security"
		id = "ac8f42d6-52da-46ec-8db1-5a5f69222a38"
		date = "2021-01-21"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Multi_EICAR.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "05c92058aab1229dfa31e006276c2c83fa484e813bdfe66edf387763797d9d57"
		score = 75
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "bb0e0bdf70ec65d98f652e2428e3567013d5413f2725a2905b372fd18da8b9dd"
		severity = 1
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword

	condition:
		all of them
}
