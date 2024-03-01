rule ELASTIC_Windows_Trojan_Cobaltstrike_417239B5 : FILE MEMORY
{
	meta:
		description = "Identifies UAC token module from Cobalt Strike"
		author = "Elastic Security"
		id = "417239b5-cf2d-4c85-a022-7a8459c26793"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L718-L764"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "fda252747359e677459d82d65c4c9c8f2ff80bc8fd6a38712f858039f3cb8dd1"
		score = 75
		quality = 51
		tags = "FILE, MEMORY"
		fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
		$a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
		$a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
		$b1 = "$pdata$is_admin_already" ascii fullword
		$b2 = "$unwind$is_admin" ascii fullword
		$b3 = "$pdata$is_admin" ascii fullword
		$b4 = "$unwind$is_admin_already" ascii fullword
		$b5 = "$pdata$RunAsAdmin" ascii fullword
		$b6 = "$unwind$RunAsAdmin" ascii fullword
		$b7 = "is_admin_already" ascii fullword
		$b8 = "is_admin" ascii fullword
		$b9 = "process_walk" ascii fullword
		$b10 = "get_current_sess" ascii fullword
		$b11 = "elevate_try" ascii fullword
		$b12 = "RunAsAdmin" ascii fullword
		$b13 = "is_ctfmon" ascii fullword
		$c1 = "_is_admin_already" ascii fullword
		$c2 = "_is_admin" ascii fullword
		$c3 = "_process_walk" ascii fullword
		$c4 = "_get_current_sess" ascii fullword
		$c5 = "_elevate_try" ascii fullword
		$c6 = "_RunAsAdmin" ascii fullword
		$c7 = "_is_ctfmon" ascii fullword
		$c8 = "_reg_query_dword" ascii fullword
		$c9 = ".drectve" ascii fullword
		$c10 = "_is_candidate" ascii fullword
		$c11 = "_SpawnAsAdmin" ascii fullword
		$c12 = "_SpawnAsAdminX64" ascii fullword

	condition:
		1 of ($a*) or 9 of ($b*) or 7 of ($c*)
}
