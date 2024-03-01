rule ELASTIC_Windows_Trojan_Cybergate_517Aac7D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cybergate (Windows.Trojan.CyberGate)"
		author = "Elastic Security"
		id = "517aac7d-2737-4917-9aa1-c0bd1c3e9801"
		date = "2022-02-28"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CyberGate.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
		logic_hash = "50e061d0c358655c03b95ccbe2d05e252501c3e6afd21dd20513019cd67e6147"
		score = 75
		quality = 48
		tags = "FILE, MEMORY"
		fingerprint = "3d998bda8e56de6fd6267abdacffece8bcf1c62c2e06540a54244dc6ea816825"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "IELOGIN.abc" ascii fullword
		$a2 = "xxxyyyzzz.dat" ascii fullword
		$a3 = "_x_X_PASSWORDLIST_X_x_" ascii fullword
		$a4 = "L$_RasDefaultCredentials#0" ascii fullword
		$a5 = "\\signons1.txt" ascii fullword

	condition:
		all of them
}
