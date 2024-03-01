rule SIGNATURE_BASE_Lightftp_Fftp_X86_64 : FILE
{
	meta:
		description = "Detects a light FTP server"
		author = "Florian Roth (Nextron Systems)"
		id = "9b62e990-1d8b-5d30-bb58-1f7f12552834"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "https://github.com/hfiref0x/LightFTP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/pup_lightftp.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f29a98a4014fc6c026aef4054bc2bee7bde2e9ad7f26f2368fdf0949f50847bb"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"

	strings:
		$s1 = "fftp.cfg" fullword wide
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword wide
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and 4 of them
}
