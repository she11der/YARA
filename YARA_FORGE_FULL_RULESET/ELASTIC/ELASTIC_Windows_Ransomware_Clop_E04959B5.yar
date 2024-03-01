rule ELASTIC_Windows_Ransomware_Clop_E04959B5 : beta FILE MEMORY
{
	meta:
		description = "Identifies CLOP ransomware in unpacked state"
		author = "Elastic Security"
		id = "e04959b5-f3da-428d-8b56-8a9817fdebe0"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Ransomware_Clop.yar#L22-L50"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "039fcb0e48898c7546588cd095fac16f06cf5e5568141aefb6db382a61e80a8d"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "7367b90772ce6db0d639835a0a54a994ef8ed351b6dadff42517ed5fbc3d0d1a"
		threat_name = "Windows.Ransomware.Clop"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "-%s\\CIopReadMe.txt" wide fullword
		$a2 = "CIopReadMe.txt" wide fullword
		$a3 = "%s-CIop^_" wide fullword
		$a4 = "%s%s.CIop" wide fullword
		$a5 = "BestChangeT0p^_-666" ascii fullword
		$a6 = ".CIop" wide fullword
		$a7 = "A%s\\ClopReadMe.txt" wide fullword
		$a8 = "%s%s.Clop" wide fullword
		$a9 = "CLOP#666" wide fullword
		$a10 = "MoneyP#666" wide fullword

	condition:
		1 of ($a*)
}
