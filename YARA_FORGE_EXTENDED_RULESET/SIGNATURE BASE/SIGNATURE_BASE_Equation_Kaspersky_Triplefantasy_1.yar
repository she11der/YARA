rule SIGNATURE_BASE_Equation_Kaspersky_Triplefantasy_1 : FILE
{
	meta:
		description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
		author = "Florian Roth (Nextron Systems)"
		id = "8d2adb3c-70e0-5768-bcfa-be64220064d9"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L75-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"
		logic_hash = "cfa3c1756c8dfb04e0a1590f76cad6d5b3878000d220c263d199322cf6a4f58a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
		$s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
		$s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
		$s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
		$s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
		$s5 = "Chrome" fullword wide
		$s6 = "StringIndex" fullword ascii
		$x1 = "itemagic.net@443" fullword wide
		$x2 = "team4heat.net@443" fullword wide
		$x5 = "62.216.152.69@443" fullword wide
		$x6 = "84.233.205.37@443" fullword wide
		$z1 = "www.microsoft.com@80" fullword wide
		$z2 = "www.google.com@80" fullword wide
		$z3 = "127.0.0.1:3128" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300000 and (( all of ($s*) and all of ($z*)) or ( all of ($s*) and 1 of ($x*)))
}
