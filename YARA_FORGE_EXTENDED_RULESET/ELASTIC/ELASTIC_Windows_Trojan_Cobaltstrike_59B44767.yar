rule ELASTIC_Windows_Trojan_Cobaltstrike_59B44767 : FILE MEMORY
{
	meta:
		description = "Identifies getsystem module from Cobalt Strike"
		author = "Elastic Security"
		id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_CobaltStrike.yar#L116-L142"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		logic_hash = "7027d0dcbdb1961d2604f29392a923957d298a047c268553599ea8c881f76a98"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
		$b1 = "getsystem failed." ascii fullword
		$b2 = "_isSystemSID" ascii fullword
		$b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
		$c1 = "getsystem failed." ascii fullword
		$c2 = "$pdata$isSystemSID" ascii fullword
		$c3 = "$unwind$isSystemSID" ascii fullword
		$c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword

	condition:
		1 of ($a*) or 3 of ($b*) or 3 of ($c*)
}
