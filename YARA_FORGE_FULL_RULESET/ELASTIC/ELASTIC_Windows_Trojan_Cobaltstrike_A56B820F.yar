rule ELASTIC_Windows_Trojan_Cobaltstrike_A56B820F : FILE MEMORY
{
	meta:
		description = "Identifies Timestomp module from Cobalt Strike"
		author = "Elastic Security"
		id = "a56b820f-0a20-4054-9c2d-008862646a78"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L650-L685"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "52de8110727c29b0f5c75cd470ce6b80ba7821d0ba78ad074536323e2e80b460"
		score = 75
		quality = 43
		tags = "FILE, MEMORY"
		fingerprint = "5418e695bcb1c37e72a7ff24a39219dc12b3fe06c29cedefd500c5e82c362b6d"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
		$b1 = "__imp_KERNEL32$GetFileTime" ascii fullword
		$b2 = "__imp_KERNEL32$SetFileTime" ascii fullword
		$b3 = "__imp_KERNEL32$CloseHandle" ascii fullword
		$b4 = "__imp_KERNEL32$CreateFileA" ascii fullword
		$b5 = "__imp_BeaconDataExtract" ascii fullword
		$b6 = "__imp_BeaconPrintf" ascii fullword
		$b7 = "__imp_BeaconDataParse" ascii fullword
		$b8 = "__imp_BeaconDataExtract" ascii fullword
		$c1 = "__imp__KERNEL32$GetFileTime" ascii fullword
		$c2 = "__imp__KERNEL32$SetFileTime" ascii fullword
		$c3 = "__imp__KERNEL32$CloseHandle" ascii fullword
		$c4 = "__imp__KERNEL32$CreateFileA" ascii fullword
		$c5 = "__imp__BeaconDataExtract" ascii fullword
		$c6 = "__imp__BeaconPrintf" ascii fullword
		$c7 = "__imp__BeaconDataParse" ascii fullword
		$c8 = "__imp__BeaconDataExtract" ascii fullword

	condition:
		1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}
