rule SIGNATURE_BASE_Wildneutron_Sample_10 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "5654a36f-8502-5e18-b8f3-94d4add466a7"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_wildneutron.yar#L225-L267"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1d3bdabb350ba5a821849893dabe5d6056bf7ba1ed6042d93174ceeaa5d6dad7"
		logic_hash = "b282b6892f9cb6769bf0e302deaa8062fd69bfd51144bc06fc9501fde9537dae"
		score = 60
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$n1 = "/c for /L %%i in (1,1,2) DO ping 127.0.0.1 -n 3 & type %%windir%%\\notepad.exe > %s & del /f %s" fullword ascii
		$s1 = "%SYSTEMROOT%\\temp\\_dbg.tmp" fullword ascii
		$s2 = "%SYSTEMROOT%\\SysWOW64\\mspool.dll" fullword ascii
		$s3 = "%SYSTEMROOT%\\System32\\dpcore16t.dll" fullword ascii
		$s4 = "%SYSTEMROOT%\\System32\\wdigestEx.dll" fullword ascii
		$s5 = "%SYSTEMROOT%\\System32\\mspool.dll" fullword ascii
		$s6 = "%SYSTEMROOT%\\System32\\kernel32.dll" fullword ascii
		$s7 = "%SYSTEMROOT%\\SysWOW64\\iastor32.exe" fullword ascii
		$s8 = "%SYSTEMROOT%\\System32\\msvcse.exe" fullword ascii
		$s9 = "%SYSTEMROOT%\\System32\\mshtaex.exe" fullword ascii
		$s10 = "%SYSTEMROOT%\\System32\\iastor32.exe" fullword ascii
		$s11 = "%SYSTEMROOT%\\SysWOW64\\mshtaex.exe" fullword ascii
		$x1 = "wdigestEx.dll" fullword ascii
		$x2 = "dpcore16t.dll" fullword ascii
		$x3 = "mspool.dll" fullword ascii
		$x4 = "msvcse.exe" fullword ascii
		$x5 = "mshtaex.exe" fullword wide
		$x6 = "iastor32.exe" fullword ascii
		$y1 = "Installer.exe" fullword ascii
		$y2 = "Info: Process %s" fullword ascii
		$y3 = "Error: GetFileTime %s 0x%x" fullword ascii
		$y4 = "Install succeeded" fullword ascii
		$y5 = "Error: RegSetValueExA 0x%x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and ($n1 or (1 of ($s*) and 1 of ($x*) and 3 of ($y*)))
}
