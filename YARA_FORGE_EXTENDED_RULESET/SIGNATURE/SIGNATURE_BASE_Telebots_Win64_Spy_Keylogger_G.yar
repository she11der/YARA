rule SIGNATURE_BASE_Telebots_Win64_Spy_Keylogger_G : FILE
{
	meta:
		description = "Detects TeleBots malware - Win64 Spy KeyLogger G"
		author = "Florian Roth (Nextron Systems)"
		id = "fd16a198-1b28-532b-a1ba-70680469ec51"
		date = "2016-12-14"
		modified = "2023-12-05"
		reference = "https://goo.gl/4if3HG"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_telebots.yar#L125-L144"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1b4db8f290bd4f943a90669afd5bff6b766d0723fb3ee9c69d7097e737beadc8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e3f134ae88f05463c4707a80f956a689fba7066bb5357f6d45cba312ad0db68e"

	strings:
		$s1 = "C:\\WRK\\GHook\\gHook\\x64\\Debug\\gHookx64.pdb" fullword ascii
		$s2 = "Install hooks error!" fullword wide
		$s4 = "%ls%d.~tmp" fullword wide
		$s5 = "[*]Window PID > %d: " fullword wide
		$s6 = "Install hooks ok!" fullword wide
		$s7 = "[!]Clipboard paste" fullword wide
		$s9 = "[*] IMAGE : %ls" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of them ) or (3 of them )
}
