rule SIGNATURE_BASE_Waterbear_4_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "c7941f92-12ee-5d57-b58e-c8caf74ca6ba"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_waterbear.yar#L45-L68"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "46c43dbdcbc183995a8cd00c9888afcdd3adb9f3caf38ed42a0af1e7df39715f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2e9cb7cadb3478edc9ef714ca4ddebb45e99d35386480e12792950f8a7a766e1"

	strings:
		$x1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;)" fullword ascii
		$s1 = "Wininet.dll InternetOpenA InternetConnectA HttpOpenRequestA HttpSendRequestA HttpQueryInfoA InternetReadFile InternetCloseHandle" fullword ascii
		$s2 = "read from pipe:%s" fullword ascii
		$s3 = "delete pipe" fullword ascii
		$s4 = "cmdcommand:%s" fullword ascii
		$s5 = "%s /c del %s" fullword ascii
		$s6 = "10.0.0.250" fullword ascii
		$s7 = "Vista/2008" fullword ascii
		$s8 = "%02X%02X%02X%02X%02X%02X%04X" fullword ascii
		$s9 = "UNKOWN" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them )
}
