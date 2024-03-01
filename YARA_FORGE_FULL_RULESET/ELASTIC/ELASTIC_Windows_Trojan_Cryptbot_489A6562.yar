rule ELASTIC_Windows_Trojan_Cryptbot_489A6562 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cryptbot (Windows.Trojan.Cryptbot)"
		author = "Elastic Security"
		id = "489a6562-870c-4105-9bb7-52ab09e5b09c"
		date = "2021-08-18"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Cryptbot.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "423563995910af04cb2c4136bf50607fc26977dfa043a84433e8bd64b3315110"
		logic_hash = "7fee3cc67419e66de790ba2ad8c3102425b3a45bdfe31801758dd38021a8439b"
		score = 75
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "f4578d79f8923706784e9d55a70ec74051273a945d2b277daa6229724defec3f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "/c rd /s /q %Temp%\\" wide fullword
		$a2 = "\\_Files\\_AllPasswords_list.txt" wide fullword
		$a3 = "\\files_\\cryptocurrency\\log.txt" wide fullword
		$a4 = "%wS\\%wS\\%wS.tmp" wide fullword
		$a5 = "%AppData%\\waves-exchange" wide fullword

	condition:
		all of them
}
