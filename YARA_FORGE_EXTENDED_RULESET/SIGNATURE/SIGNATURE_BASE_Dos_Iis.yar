rule SIGNATURE_BASE_Dos_Iis : FILE
{
	meta:
		description = "Chinese Hacktool Set - file iis.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8813b7a2-0d44-5f26-80ab-0f493c09a027"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1992-L2011"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"
		logic_hash = "d6852af79eac659f4dfa3019793290e0498739f02a06c5540cd7d2c65b46b960"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "program terming" fullword ascii
		$s3 = "WinSta0\\Defau" fullword ascii
		$s4 = "* FROM IIsWebInfo" ascii
		$s5 = "www.icehack." ascii
		$s6 = "wmiprvse.exe" fullword ascii
		$s7 = "Pid: %d" ascii

	condition:
		uint16(0)==0x5a4d and filesize <70KB and all of them
}
