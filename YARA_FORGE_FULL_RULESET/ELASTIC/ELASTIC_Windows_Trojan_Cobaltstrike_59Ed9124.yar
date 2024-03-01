rule ELASTIC_Windows_Trojan_Cobaltstrike_59Ed9124 : FILE MEMORY
{
	meta:
		description = "Identifies PsExec module from Cobalt Strike"
		author = "Elastic Security"
		id = "59ed9124-bc20-4ea6-b0a7-63ee3359e69c"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L525-L560"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "a50fd291f5f1bf7ec41b1938a32473a23c3c082018b86eab87aff0d95b26ba06"
		score = 75
		quality = 43
		tags = "FILE, MEMORY"
		fingerprint = "7823e3b98e55a83bf94b0f07e4c116dbbda35adc09fa0b367f8a978a80c2efff"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
		$b1 = "__imp_BeaconDataExtract" ascii fullword
		$b2 = "__imp_BeaconDataParse" ascii fullword
		$b3 = "__imp_BeaconDataParse" ascii fullword
		$b4 = "__imp_BeaconDataParse" ascii fullword
		$b5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
		$b6 = "__imp_ADVAPI32$DeleteService" ascii fullword
		$b7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
		$b8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
		$c1 = "__imp__BeaconDataExtract" ascii fullword
		$c2 = "__imp__BeaconDataParse" ascii fullword
		$c3 = "__imp__BeaconDataParse" ascii fullword
		$c4 = "__imp__BeaconDataParse" ascii fullword
		$c5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
		$c6 = "__imp__ADVAPI32$DeleteService" ascii fullword
		$c7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
		$c8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword

	condition:
		1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}
