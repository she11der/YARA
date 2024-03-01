rule SIGNATURE_BASE_Dos_C : FILE
{
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2e8319de-fe54-5083-968c-4707d127f072"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1468-L1487"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"
		logic_hash = "2865b50e6a323462fab39bd84571939c618cf6f00e147039f6e699ba4d195a00"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "!Win32 .EXE." fullword ascii
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii
		$s3 = "XOLEHLP.dll" fullword ascii
		$s4 = "</body></html>" fullword ascii
		$s8 = "DtcGetTransactionManagerExA" fullword ascii
		$s9 = "GetUserNameA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
