rule ELASTIC_Windows_Trojan_Cobaltstrike_2B8Cddf8 : FILE MEMORY
{
	meta:
		description = "Identifies dll load module from Cobalt Strike"
		author = "Elastic Security"
		id = "2b8cddf8-ca7a-4f85-be9d-6d8534d0482e"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L79-L114"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "5502c06d33b93bae3bc25ba7dd6a5a9a3b0b2b43bb7e867e601ecb206bf503ed"
		score = 75
		quality = 43
		tags = "FILE, MEMORY"
		fingerprint = "0d7d28d79004ca61b0cfdcda29bd95e3333e6fc6e6646a3f6ba058aa01bee188"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
		$b1 = "__imp_BeaconErrorDD" ascii fullword
		$b2 = "__imp_BeaconErrorNA" ascii fullword
		$b3 = "__imp_BeaconErrorD" ascii fullword
		$b4 = "__imp_BeaconDataInt" ascii fullword
		$b5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
		$b6 = "__imp_KERNEL32$OpenProcess" ascii fullword
		$b7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
		$b8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
		$c1 = "__imp__BeaconErrorDD" ascii fullword
		$c2 = "__imp__BeaconErrorNA" ascii fullword
		$c3 = "__imp__BeaconErrorD" ascii fullword
		$c4 = "__imp__BeaconDataInt" ascii fullword
		$c5 = "__imp__KERNEL32$WriteProcessMemory" ascii fullword
		$c6 = "__imp__KERNEL32$OpenProcess" ascii fullword
		$c7 = "__imp__KERNEL32$CreateRemoteThread" ascii fullword
		$c8 = "__imp__KERNEL32$VirtualAllocEx" ascii fullword

	condition:
		1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}
