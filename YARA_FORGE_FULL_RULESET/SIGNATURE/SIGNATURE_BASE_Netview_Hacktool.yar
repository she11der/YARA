import "pe"

rule SIGNATURE_BASE_Netview_Hacktool : FILE
{
	meta:
		description = "Network domain enumeration tool - often used by attackers - file Nv.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "087e2fd7-726e-5c6b-ba99-e20dd3337d6a"
		date = "2016-03-07"
		modified = "2023-12-05"
		reference = "https://github.com/mubix/netview"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3084-L3107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "52cec98839c3b7d9608c865cfebc904b4feae0bada058c2e8cdbd561cfa1420a"
		logic_hash = "dc27d2358937d736823891c9d5c3f41f83a6f4e72d35fae0983435effda2141a"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[+] %ws - Target user found - %s\\%s" fullword wide
		$s2 = "[*] -g used without group specified - using \"Domain Admins\"" fullword ascii
		$s3 = "[*] -i used without interval specified - ignoring" fullword ascii
		$s4 = "[+] %ws - Session - %s from %s - Active: %d - Idle: %d" fullword wide
		$s5 = "[+] %ws - Backup Domain Controller" fullword wide
		$s6 = "[-] %ls - Share - Error: %ld" fullword wide
		$s7 = "[-] %ls - Session - Error: %ld" fullword wide
		$s8 = "[+] %s - OS Version - %d.%d" fullword ascii
		$s9 = "Enumerating Logged-on Users" fullword ascii
		$s10 = ": Specifies a domain to pull a list of hosts from" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 2 of them ) or 3 of them
}
