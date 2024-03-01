rule SIGNATURE_BASE_Dos_Iis7 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file iis7.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8813b7a2-0d44-5f26-80ab-0f493c09a027"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L621-L638"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
		logic_hash = "e0cbcb63cd2a542e6394792070392d393b2a3485f5a5ef3c6ba0f113ae9270ec"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s5 = "WHOAMI" ascii
		$s13 = "WinSta0\\Default" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <140KB and all of them
}
