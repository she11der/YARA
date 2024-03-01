rule ELASTIC_Windows_Trojan_Cobaltstrike_92F05172 : FILE MEMORY
{
	meta:
		description = "Identifies UAC cmstp module from Cobalt Strike"
		author = "Elastic Security"
		id = "92f05172-f15c-4077-a958-b8490378bf08"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_CobaltStrike.yar#L687-L716"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		logic_hash = "7f0ff4ee14a043d72810826ab9d2b90b0f66724550ba9d3cdd2abe749f4874d0"
		score = 75
		quality = 63
		tags = "FILE, MEMORY"
		fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
		$b1 = "elevate_cmstp" ascii fullword
		$b2 = "$pdata$elevate_cmstp" ascii fullword
		$b3 = "$unwind$elevate_cmstp" ascii fullword
		$c1 = "_elevate_cmstp" ascii fullword
		$c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
		$c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
		$c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
		$c5 = "OLDNAMES"
		$c6 = "__imp__BeaconDataParse" ascii fullword
		$c7 = "_willAutoElevate" ascii fullword

	condition:
		1 of ($a*) or 3 of ($b*) or 4 of ($c*)
}
