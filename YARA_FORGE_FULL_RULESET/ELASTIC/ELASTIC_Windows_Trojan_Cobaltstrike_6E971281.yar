rule ELASTIC_Windows_Trojan_Cobaltstrike_6E971281 : FILE MEMORY
{
	meta:
		description = "Identifies Interfaces module from Cobalt Strike"
		author = "Elastic Security"
		id = "6e971281-3ee3-402f-8a72-745ec8fb91fb"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L170-L201"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "f204965c0118dbdfe7e134d319c92b30d22585e888609ff31df90643116a2c38"
		score = 75
		quality = 51
		tags = "FILE, MEMORY"
		fingerprint = "62d97cf73618a1b4d773d5494b2761714be53d5cda774f9a96eaa512c8d5da12"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
		$b1 = "__imp_BeaconFormatAlloc" ascii fullword
		$b2 = "__imp_BeaconFormatPrintf" ascii fullword
		$b3 = "__imp_BeaconOutput" ascii fullword
		$b4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
		$b5 = "__imp_KERNEL32$LocalFree" ascii fullword
		$b6 = "__imp_LoadLibraryA" ascii fullword
		$c1 = "__imp__BeaconFormatAlloc" ascii fullword
		$c2 = "__imp__BeaconFormatPrintf" ascii fullword
		$c3 = "__imp__BeaconOutput" ascii fullword
		$c4 = "__imp__KERNEL32$LocalAlloc" ascii fullword
		$c5 = "__imp__KERNEL32$LocalFree" ascii fullword
		$c6 = "__imp__LoadLibraryA" ascii fullword

	condition:
		1 of ($a*) or 4 of ($b*) or 4 of ($c*)
}
