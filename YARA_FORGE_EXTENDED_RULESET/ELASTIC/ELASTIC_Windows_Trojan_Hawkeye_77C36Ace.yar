rule ELASTIC_Windows_Trojan_Hawkeye_77C36Ace : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Hawkeye (Windows.Trojan.Hawkeye)"
		author = "Elastic Security"
		id = "77c36ace-3857-43f8-a6de-596ba7964b6f"
		date = "2021-08-16"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_Hawkeye.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "28e28025060f1bafd4eb96c7477cab73497ca2144b52e664b254c616607d94cd"
		logic_hash = "e8c1060efde0c4a073247d03a19dedb1c0acc8506fbf6eac93ac44f00fc73be1"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "c9a1c61b4fa78c46d493e1b307e9950bd714ba4e5a6249f15a3b86a74b7638e5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Logger - Key Recorder - [" wide fullword
		$a2 = "http://whatismyipaddress.com/" wide fullword
		$a3 = "Keylogger Enabled: " wide fullword
		$a4 = "LoadPasswordsSeaMonkey" wide fullword
		$a5 = "\\.minecraft\\lastlogin" wide fullword

	condition:
		all of them
}
