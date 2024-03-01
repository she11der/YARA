rule ELASTIC_Windows_Trojan_Icedid_08530E24 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "08530e24-5b84-40a4-bc5c-ead74762faf8"
		date = "2021-03-21"
		modified = "2021-08-23"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_IcedID.yar#L67-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "31db92c7920e82e49a968220480e9f130dea9b386083b78a79985b554ecdc6e4"
		logic_hash = "a63511edde9d873e184ddb4720b4752b0e7df4bdb2114b05c16f2ca0594eb6b8"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "f2b5768b87eec7c1c9730cc99364cc90e87fd9201bf374418ad008fd70d321af"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "c:\\ProgramData\\" ascii fullword
		$a2 = "loader_dll_64.dll" ascii fullword
		$a3 = "aws.amazon.com" wide fullword
		$a4 = "Cookie: __gads=" wide fullword
		$b1 = "LookupAccountNameW" ascii fullword
		$b2 = "GetUserNameA" ascii fullword
		$b3 = "; _gat=" wide fullword
		$b4 = "; _ga=" wide fullword
		$b5 = "; _u=" wide fullword
		$b6 = "; __io=" wide fullword
		$b7 = "; _gid=" wide fullword
		$b8 = "%s%u" wide fullword
		$b9 = "i\\|9*" ascii fullword
		$b10 = "WinHttpSetStatusCallback" ascii fullword

	condition:
		all of ($a*) and 5 of ($b*)
}
