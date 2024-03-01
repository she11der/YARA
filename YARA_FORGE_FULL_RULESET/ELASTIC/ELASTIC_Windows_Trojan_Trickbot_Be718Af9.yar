rule ELASTIC_Windows_Trojan_Trickbot_Be718Af9 : FILE MEMORY
{
	meta:
		description = "Targets permadll module used to fingerprint BIOS/firmaware data"
		author = "Elastic Security"
		id = "be718af9-5995-4ae2-ba55-504e88693c96"
		date = "2021-03-30"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Trickbot.yar#L898-L921"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "c1f1bc58456cff7413d7234e348d47a8acfdc9d019ae7a4aba1afc1b3ed55ffa"
		logic_hash = "d020f7d1637fc4ee3246e97c9acae0be1782e688154bd109f53f807211beebd7"
		score = 75
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "047b1c64b8be17d4a6030ab2944ad715380f53a8a6dd9c8887f198693825a81d"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "user_platform_check.dll" ascii fullword
		$a2 = "<moduleconfig><nohead>yes</nohead></moduleconfig>" ascii fullword
		$a3 = "DDEADFDEEEEE"
		$a4 = "\\`Ruuuuu_Exs|_" ascii fullword
		$a5 = "\"%pueuu%" ascii fullword

	condition:
		3 of ($a*)
}
