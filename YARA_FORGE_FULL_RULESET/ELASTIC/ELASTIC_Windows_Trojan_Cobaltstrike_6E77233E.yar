rule ELASTIC_Windows_Trojan_Cobaltstrike_6E77233E : FILE MEMORY
{
	meta:
		description = "Identifies Kerberos module from Cobalt Strike"
		author = "Elastic Security"
		id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L234-L269"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "93aa11523b794402b257d02d4f9edc5ad320bfdb5b8b0f671ff08f399ef9e674"
		score = 75
		quality = 63
		tags = "FILE, MEMORY"
		fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
		$a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
		$a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
		$a4 = "command_kerberos_ticket_use" ascii fullword
		$a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
		$a6 = "command_kerberos_ticket_purge" ascii fullword
		$a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
		$a8 = "$unwind$kerberos_init" ascii fullword
		$a9 = "$unwind$KerberosTicketUse" ascii fullword
		$a10 = "KerberosTicketUse" ascii fullword
		$a11 = "$unwind$KerberosTicketPurge" ascii fullword
		$b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
		$b2 = "_command_kerberos_ticket_use" ascii fullword
		$b3 = "_command_kerberos_ticket_purge" ascii fullword
		$b4 = "_kerberos_init" ascii fullword
		$b5 = "_KerberosTicketUse" ascii fullword
		$b6 = "_KerberosTicketPurge" ascii fullword
		$b7 = "_LsaCallKerberosPackage" ascii fullword

	condition:
		5 of ($a*) or 3 of ($b*)
}
