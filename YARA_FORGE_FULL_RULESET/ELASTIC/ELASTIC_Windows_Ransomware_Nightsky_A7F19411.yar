rule ELASTIC_Windows_Ransomware_Nightsky_A7F19411 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Nightsky (Windows.Ransomware.Nightsky)"
		author = "Elastic Security"
		id = "a7f19411-4c28-4cc7-b60c-ef51cb10b905"
		date = "2022-01-11"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Ransomware_Nightsky.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "1fca1cd04992e0fcaa714d9dfa97323d81d7e3d43a024ec37d1c7a2767a17577"
		logic_hash = "defc7ab43035c663302edfda60a4b57cb301b3d61662afe3ce1de2ac93cfc3e2"
		score = 75
		quality = 48
		tags = "FILE, MEMORY"
		fingerprint = "0f2aac3a538a921b78f7c2521adf65678830abab8ec8b360ac3dddae5fbc4756"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\NightSkyReadMe.hta" wide fullword
		$a2 = ".nightsky" wide fullword
		$a3 = "<h1 id=\"nightsky\"><center><span style=\"color: black; font-size: 48pt\">NIGHT SKY</span></center>" ascii fullword
		$a4 = "URL:https://contact.nightsky.cyou" ascii fullword

	condition:
		2 of them
}
