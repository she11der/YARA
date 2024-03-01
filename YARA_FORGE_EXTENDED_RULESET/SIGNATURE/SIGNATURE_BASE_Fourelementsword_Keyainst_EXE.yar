rule SIGNATURE_BASE_Fourelementsword_Keyainst_EXE : FILE
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "175fe2b0-3c76-5464-9a1a-218a09b25a5a"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_four_element_sword.yar#L70-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
		logic_hash = "1491de3241a81cce4d80d6dc23886f1d8bf316112c48652a8138aa4cbadbb174"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii
		$s1 = "ShellExecuteA" fullword ascii
		$s2 = "GetStartupInfoA" fullword ascii
		$s3 = "SHELL32.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <48KB and $x1) or ( all of them )
}
