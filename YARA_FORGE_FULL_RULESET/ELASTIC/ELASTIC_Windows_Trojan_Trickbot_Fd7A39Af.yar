rule ELASTIC_Windows_Trojan_Trickbot_Fd7A39Af : FILE MEMORY
{
	meta:
		description = "Targets wormDll64.dll module containing spreading functionality"
		author = "Elastic Security"
		id = "fd7a39af-c6ea-4682-a00a-01f775c3bb8d"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Trickbot.yar#L705-L739"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "d5bb8d94b71d475b5eb9bb4235a428563f4104ea49f11ef02c8a08d2e859fd68"
		logic_hash = "15cb286504e6167c78e194488555f565965a03e7714fe16692a115df26985a01"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "3f2e654f2ffdd940c27caec3faeb4bda24c797a17d0987378e36c1e16fadc772"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "module64.dll" ascii fullword
		$a2 = "worming.png" wide
		$a3 = "Size - %d kB" ascii fullword
		$a4 = "[+] %s -" wide fullword
		$a5 = "%s\\system32" ascii fullword
		$a6 = "[-] %s" wide fullword
		$a7 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig>" ascii fullword
		$a8 = "*****MACHINE IN WORKGROUP*****" wide fullword
		$a9 = "*****MACHINE IN DOMAIN*****" wide fullword
		$a10 = "\\\\%s\\IPC$" ascii fullword
		$a11 = "Windows 5" ascii fullword
		$a12 = "InfMach" ascii fullword
		$a13 = "%s x64" wide fullword
		$a14 = "%s x86" wide fullword
		$a15 = "s(&(objectCategory=computer)(userAccountControl:" wide fullword
		$a16 = "------MACHINE IN D-N------" wide fullword

	condition:
		5 of ($a*)
}
