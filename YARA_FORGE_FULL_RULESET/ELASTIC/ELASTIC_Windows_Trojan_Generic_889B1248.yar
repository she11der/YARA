rule ELASTIC_Windows_Trojan_Generic_889B1248 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "889b1248-a694-4c9b-8792-c04e582e814c"
		date = "2022-03-11"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Generic.yar#L111-L132"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "a48d57a139c7e3efa0c47f8699e2cf6159dc8cdd823b16ce36257eb8c9d14d53"
		logic_hash = "b3bb93b95377d6c6606d29671395b78c0954cc47d5cc450436799638d0458469"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "a5e0c2bbd6a297c01f31eccabcbe356730f50f074587f679da6caeca99e54bc1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "BELARUS-VIRUS-MAKER" ascii fullword
		$a2 = "C:\\windows\\temp\\" ascii fullword
		$a3 = "~c~a~n~n~a~b~i~s~~i~s~~n~o~t~~a~~d~r~u~g~" ascii fullword
		$a4 = "untInfector" ascii fullword

	condition:
		all of them
}
